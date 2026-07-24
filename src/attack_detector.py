#!/usr/bin/env python3
"""
Detector de ataques para un laboratorio controlado.

Monitorea en tiempo real:
- Apache access.log: SQLMap, patrones de SQL Injection y fuerza bruta HTTP POST.
- vsftpd.log: intentos fallidos repetidos de inicio de sesión FTP.
- auth.log: intentos fallidos repetidos de SSH (deshabilitado por defecto).

Cuando se supera un umbral, crea una regla en una cadena dedicada de iptables.
No requiere paquetes de Python externos.
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import logging
import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote_plus, urlsplit

# Configuración por defecto de la herramienta.
# Define umbrales (threshold), tiempos de ventana (window_seconds) y rutas de archivos de log.
# Esta configuración se sobrescribe parcialmente con los valores que el usuario tenga en config.json.
DEFAULT_CONFIG: dict[str, Any] = {
    "dry_run": False,
    "poll_interval_seconds": 0.25,
    "block_scope": "service",
    "iptables_chain": "ATTACK_DETECTOR",
    "state_file": "/var/lib/attack-detector/blocked.json",
    "events_file": "/var/log/attack-detector/events.jsonl",
    "allowlist": [
        "127.0.0.0/8",
        "::1/128"
    ],
    "logs": {
        "apache": ["/var/log/apache2/access.log"],
        "vsftpd": ["/var/log/vsftpd.log"],
        "auth": ["/var/log/auth.log"]
    },
    "detectors": {
        "sqlmap_user_agent": {
            "enabled": True,
            "threshold": 1,
            "window_seconds": 10
        },
        "sqli_payload": {
            "enabled": True,
            "threshold": 2,
            "window_seconds": 30
        },
        "hydra_http_user_agent": {
            "enabled": True,
            "threshold": 3,
            "window_seconds": 15
        },
        "web_bruteforce": {
            "enabled": True,
            "threshold": 8,
            "window_seconds": 60,
            "paths": ["/sistema/index.php"],
            "failure_statuses": [200]
        },
        "ftp_bruteforce": {
            "enabled": True,
            "threshold": 6,
            "window_seconds": 60
        },
        "ssh_bruteforce": {
            "enabled": False,
            "threshold": 6,
            "window_seconds": 60
        }
    }
}

# Expresión regular para parsear las líneas del archivo access.log de Apache (formato combinado).
# Captura la IP de origen, el método HTTP (GET/POST), la ruta destino, el código de estado HTTP y el User-Agent.
APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<target>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+\S+\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# Expresión regular para detectar intentos fallidos de login en vsftpd.log.
# Ejemplo de línea: 'FAIL LOGIN: Client "198.51.100.30"'
FTP_FAIL_RE = re.compile(
    r'FAIL LOGIN:\s+Client\s+"(?P<ip>[^"]+)"',
    re.IGNORECASE
)

# Expresión regular para detectar fallos de autenticación por SSH en auth.log.
# Ejemplo de línea: 'Failed password for invalid user admin from 198.51.100.40 port 54321 ssh2'
SSH_FAIL_RE = re.compile(
    r'Failed password .*? from (?P<ip>[0-9a-fA-F:.]+)\s+port\s+\d+',
    re.IGNORECASE
)

# Expresión regular que agrupa las palabras reservadas o técnicas más comunes
# de los ataques de Inyección SQL. Usada contra la URL solicitada.
SQLI_RE = re.compile(
    r"""
    (?:
        \bunion(?:\s+all)?\s+select\b
        |\bor\s+['"]?\d+['"]?\s*=\s*['"]?\d+
        |\band\s+['"]?\d+['"]?\s*=\s*['"]?\d+
        |information_schema
        |\bsleep\s*\(
        |\bbenchmark\s*\(
        |\bload_file\s*\(
        |\binto\s+outfile\b
        |\bextractvalue\s*\(
        |\bupdatexml\s*\(
    )
    """,
    re.IGNORECASE | re.VERBOSE
)

def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Realiza una mezcla profunda (deep merge) de dos diccionarios, ideal para combinar la configuración base con la del usuario."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

def load_config(path: str) -> dict[str, Any]:
    """Carga la configuración desde un archivo JSON y la combina con DEFAULT_CONFIG."""
    config = copy.deepcopy(DEFAULT_CONFIG)
    config_path = Path(path)
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            user_config = json.load(file)
        config = deep_merge(config, user_config)
    return config

def normalize_ip(raw: str) -> str | None:
    """Extrae y normaliza una dirección IP (IPv4 o IPv6), eliminando corchetes u otros caracteres."""
    value = raw.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None

class SlidingWindow:
    """Implementa una ventana deslizante basada en tiempo para contar eventos repetitivos dentro de un límite de segundos."""
    def __init__(self) -> None:
        self.events: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def add(self, detector: str, ip: str, window_seconds: int) -> int:
        """Añade un nuevo evento a la ventana actual y elimina los que ya expiraron (fuera de window_seconds). Retorna el conteo actual."""
        now = time.monotonic()
        key = (detector, ip)
        bucket = self.events[key]
        bucket.append(now)
        minimum = now - window_seconds
        while bucket and bucket[0] < minimum:
            bucket.popleft()
        return len(bucket)

class DetectorEngine:
    """Analiza líneas ya leídas y llama a on_detection cuando encuentra un ataque."""

    def __init__(
        self,
        config: dict[str, Any],
        on_detection: Callable[..., bool],
    ) -> None:
        self.config = config
        self.on_detection = on_detection
        self.windows = SlidingWindow()
        self.allow_networks = [
            ipaddress.ip_network(item, strict=False)
            for item in config.get("allowlist", [])
        ]

    def is_allowed(self, ip: str) -> bool:
        address = ipaddress.ip_address(ip)
        return any(
            address.version == network.version and address in network
            for network in self.allow_networks
        )

    def _count_and_maybe_trigger(
        self,
        detector_name: str,
        ip: str,
        attack_type: str,
        service: str,
        ports: list[int],
        evidence: str,
    ) -> None:
        detector = self.config["detectors"].get(detector_name, {})
        if not detector.get("enabled", False):
            return
        if self.is_allowed(ip):
            logging.info("Evento ignorado por allowlist: %s (%s)", ip, detector_name)
            return

        count = self.windows.add(
            detector_name,
            ip,
            int(detector.get("window_seconds", 60)),
        )
        threshold = int(detector.get("threshold", 1))
        if count >= threshold:
            self.on_detection(
                ip=ip,
                attack_type=attack_type,
                detector=detector_name,
                service=service,
                ports=ports,
                count=count,
                threshold=threshold,
                evidence=evidence[:1000],
            )

    def process(self, source: str, line: str) -> None:
        if source == "apache":
            self._process_apache(line)
        elif source == "vsftpd":
            self._process_ftp(line)
        elif source == "auth":
            self._process_auth(line)

    def _process_apache(self, line: str) -> None:
        match = APACHE_RE.match(line)
        if not match:
            return

        data = match.groupdict()
        ip = normalize_ip(data["ip"])
        if not ip:
            return

        method = data["method"].upper()
        target = data["target"]
        status = int(data["status"])
        user_agent = data["ua"]
        decoded_target = unquote_plus(target)
        path = urlsplit(target).path

        if "sqlmap" in user_agent.lower():
            self._count_and_maybe_trigger(
                detector_name="sqlmap_user_agent",
                ip=ip,
                attack_type="SQL Injection con SQLMap",
                service="HTTP/HTTPS",
                ports=[80, 443],
                evidence=line,
            )

        if SQLI_RE.search(decoded_target):
            self._count_and_maybe_trigger(
                detector_name="sqli_payload",
                ip=ip,
                attack_type="Patrones de SQL Injection",
                service="HTTP/HTTPS",
                ports=[80, 443],
                evidence=line,
            )

        if "hydra" in user_agent.lower():
            self._count_and_maybe_trigger(
                detector_name="hydra_http_user_agent",
                ip=ip,
                attack_type="Fuerza bruta HTTP con Hydra",
                service="HTTP/HTTPS",
                ports=[80, 443],
                evidence=line,
            )

        web_cfg = self.config["detectors"].get("web_bruteforce", {})
        monitored_paths = set(web_cfg.get("paths", []))
        failure_statuses = {int(value) for value in web_cfg.get("failure_statuses", [200])}
        if (
            method == "POST"
            and path in monitored_paths
            and status in failure_statuses
        ):
            self._count_and_maybe_trigger(
                detector_name="web_bruteforce",
                ip=ip,
                attack_type="Fuerza bruta contra formulario web",
                service="HTTP/HTTPS",
                ports=[80, 443],
                evidence=line,
            )

    def _process_ftp(self, line: str) -> None:
        match = FTP_FAIL_RE.search(line)
        if not match:
            return
        ip = normalize_ip(match.group("ip"))
        if not ip:
            return
        self._count_and_maybe_trigger(
            detector_name="ftp_bruteforce",
            ip=ip,
            attack_type="Fuerza bruta FTP",
            service="FTP",
            ports=[21],
            evidence=line,
        )

    def _process_auth(self, line: str) -> None:
        match = SSH_FAIL_RE.search(line)
        if not match:
            return
        ip = normalize_ip(match.group("ip"))
        if not ip:
            return
        self._count_and_maybe_trigger(
            detector_name="ssh_bruteforce",
            ip=ip,
            attack_type="Fuerza bruta SSH",
            service="SSH",
            ports=[22],
            evidence=line,
        )

class Firewall:
    """Administra una cadena dedicada de iptables y persiste los bloqueos."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.dry_run = bool(config.get("dry_run", False))
        self.chain = str(config.get("iptables_chain", "ATTACK_DETECTOR"))
        self.block_scope = str(config.get("block_scope", "service"))
        self.state_path = Path(config["state_file"])
        self.events_path = Path(config["events_file"])
        self.iptables = shutil.which("iptables") or "/usr/sbin/iptables"
        self.records = self._load_state()

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.events_path.parent.mkdir(parents=True, exist_ok=True)

        if not self.dry_run:
            if os.geteuid() != 0:
                raise PermissionError("La herramienta debe ejecutarse como root para usar iptables.")
            if not Path(self.iptables).exists():
                raise FileNotFoundError("No se encontró iptables. Instálelo antes de iniciar.")
            self.ensure_chain()
            self.restore_state()

    def _run(self, args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
        command = [self.iptables, "--wait", "5", *args]
        logging.debug("Ejecutando: %s", shlex.join(command))
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=check,
        )

    def ensure_chain(self) -> None:
        if self._run(["-nL", self.chain]).returncode != 0:
            self._run(["-N", self.chain], check=True)
        if self._run(["-C", "INPUT", "-j", self.chain]).returncode != 0:
            self._run(["-I", "INPUT", "1", "-j", self.chain], check=True)

    def _load_state(self) -> list[dict[str, Any]]:
        if not self.state_path.exists():
            return []
        try:
            with self.state_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError):
            logging.exception("No se pudo leer el estado de bloqueos.")
            return []

    def _save_state(self) -> None:
        temporary = self.state_path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as file:
            json.dump(self.records, file, indent=2, ensure_ascii=False)
        temporary.replace(self.state_path)

    def _rule_args(self, record: dict[str, Any]) -> list[str]:
        args = ["-s", record["ip"]]
        ports = record.get("ports", [])
        if record.get("scope") == "service" and ports:
            args += [
                "-p", "tcp",
                "-m", "multiport",
                "--dports", ",".join(str(port) for port in ports),
            ]
        args += [
            "-m", "comment",
            "--comment", record["comment"],
            "-j", "DROP",
        ]
        return args

    def _rule_exists(self, record: dict[str, Any]) -> bool:
        return self._run(["-C", self.chain, *self._rule_args(record)]).returncode == 0

    def restore_state(self) -> None:
        for record in self.records:
            if not self._rule_exists(record):
                self._run(["-I", self.chain, "1", *self._rule_args(record)], check=True)

    def block(
        self,
        ip: str,
        attack_type: str,
        detector: str,
        service: str,
        ports: list[int],
        evidence: str,
        count: int,
        threshold: int,
    ) -> bool:
        scope = "all" if self.block_scope == "all" else "service"
        effective_ports = [] if scope == "all" else sorted(set(ports))

        # No duplica un bloqueo equivalente para la misma IP y puertos.
        for record in self.records:
            if (
                record.get("ip") == ip
                and record.get("scope") == scope
                and record.get("ports", []) == effective_ports
            ):
                return False

        safe_detector = re.sub(r"[^a-zA-Z0-9_-]", "_", detector)[:40]
        record = {
            "ip": ip,
            "scope": scope,
            "ports": effective_ports,
            "comment": f"attack-detector:{safe_detector}",
            "attack_type": attack_type,
            "service": service,
            "detector": detector,
            "blocked_at_utc": datetime.now(timezone.utc).isoformat(),
        }

        if not self.dry_run:
            self._run(["-I", self.chain, "1", *self._rule_args(record)], check=True)
            self.records.append(record)
            self._save_state()

        event = {
            **record,
            "action": "DRY_RUN" if self.dry_run else "BLOCKED",
            "count": count,
            "threshold": threshold,
            "evidence": evidence,
        }
        self.write_event(event)

        logging.warning(
            "%s IP=%s ataque=%s servicio=%s puertos=%s conteo=%s/%s",
            event["action"],
            ip,
            attack_type,
            service,
            effective_ports or "TODOS",
            count,
            threshold,
        )
        return True

    def write_event(self, event: dict[str, Any]) -> None:
        event["recorded_at_utc"] = datetime.now(timezone.utc).isoformat()
        with self.events_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")

    def unblock(self, ip: str) -> int:
        normalized = normalize_ip(ip)
        if not normalized:
            raise ValueError(f"IP inválida: {ip}")

        removed = 0
        remaining: list[dict[str, Any]] = []
        for record in self.records:
            if record.get("ip") != normalized:
                remaining.append(record)
                continue

            if not self.dry_run and self._rule_exists(record):
                result = self._run(["-D", self.chain, *self._rule_args(record)])
                if result.returncode != 0:
                    logging.error("No se pudo eliminar una regla: %s", result.stderr.strip())
                    remaining.append(record)
                    continue
            removed += 1

        self.records = remaining
        if not self.dry_run:
            self._save_state()
        return removed

    def flush(self) -> None:
        if not self.dry_run:
            self.ensure_chain()
            self._run(["-F", self.chain], check=True)
            self.records = []
            self._save_state()

    def print_blocks(self) -> None:
        print(json.dumps(self.records, indent=2, ensure_ascii=False))

class LogFollower(threading.Thread):
    """Sigue un archivo tipo tail -F, tolerando creación tardía y rotación."""

    def __init__(
        self,
        source: str,
        path: str,
        output: queue.Queue[tuple[str, str]],
        stop_event: threading.Event,
        poll_interval: float,
    ) -> None:
        super().__init__(daemon=True, name=f"follow-{source}-{Path(path).name}")
        self.source = source
        self.path = Path(path)
        self.output = output
        self.stop_event = stop_event
        self.poll_interval = poll_interval

    def run(self) -> None:
        file = None
        inode = None
        first_open = True

        while not self.stop_event.is_set():
            try:
                if file is None:
                    stat = self.path.stat()
                    file = self.path.open("r", encoding="utf-8", errors="replace")
                    inode = stat.st_ino
                    if first_open:
                        file.seek(0, os.SEEK_END)
                        first_open = False
                    else:
                        file.seek(0)
                    logging.info("Monitoreando %s (%s)", self.path, self.source)

                line = file.readline()
                if line:
                    self.output.put((self.source, line.rstrip("\n")))
                    continue

                try:
                    stat = self.path.stat()
                    if stat.st_ino != inode or stat.st_size < file.tell():
                        file.close()
                        file = None
                        inode = None
                        continue
                except FileNotFoundError:
                    file.close()
                    file = None
                    inode = None

            except FileNotFoundError:
                logging.warning("Esperando a que exista el log: %s", self.path)
                file = None
            except PermissionError:
                logging.exception("Sin permisos para leer %s", self.path)
                self.stop_event.set()
            except OSError:
                logging.exception("Error siguiendo %s", self.path)
                if file:
                    file.close()
                file = None

            self.stop_event.wait(self.poll_interval)

        if file:
            file.close()

def validate_config(config: dict[str, Any]) -> None:
    """Valida la integridad y lógica de la configuración antes de arrancar, deteniendo la ejecución si hay errores."""
    if config.get("block_scope") not in {"service", "all"}:
        raise ValueError('block_scope debe ser "service" o "all".')
    for network in config.get("allowlist", []):
        ipaddress.ip_network(network, strict=False)
    for name, detector in config.get("detectors", {}).items():
        if int(detector.get("threshold", 1)) < 1:
            raise ValueError(f"Umbral inválido en {name}.")
        if int(detector.get("window_seconds", 1)) < 1:
            raise ValueError(f"Ventana inválida en {name}.")

def run_monitor(config: dict[str, Any]) -> int:
    """
    Función principal del demonio. Orquesta la inicialización del firewall, 
    crea los hilos seguidores (LogFollower) para cada archivo de log, 
    y procesa continuamente las líneas en el motor de detección (DetectorEngine).
    Atrapa señales del sistema operativo para un apagado limpio.
    """
    validate_config(config)
    firewall = Firewall(config)
    engine = DetectorEngine(config, firewall.block)

    stop_event = threading.Event()
    lines: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=10000)

    def stop_handler(signum: int, _frame: Any) -> None:
        logging.info("Señal %s recibida; deteniendo...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    followers: list[LogFollower] = []
    poll_interval = float(config.get("poll_interval_seconds", 0.25))
    for source, paths in config.get("logs", {}).items():
        for path in paths:
            follower = LogFollower(source, path, lines, stop_event, poll_interval)
            follower.start()
            followers.append(follower)

    logging.info(
        "Detector iniciado. dry_run=%s block_scope=%s cadena=%s",
        config.get("dry_run"),
        config.get("block_scope"),
        config.get("iptables_chain"),
    )

    while not stop_event.is_set():
        try:
            source, line = lines.get(timeout=0.5)
            engine.process(source, line)
        except queue.Empty:
            continue
        except Exception:
            logging.exception("Error procesando una línea de log.")

    for follower in followers:
        follower.join(timeout=2)
    logging.info("Detector detenido.")
    return 0

def build_parser() -> argparse.ArgumentParser:
    """Construye y configura el interpretador de argumentos de línea de comandos (CLI flags)."""
    parser = argparse.ArgumentParser(description="Detector de ataques basado en logs.")
    parser.add_argument(
        "--config",
        default="/etc/attack-detector/config.json",
        help="Ruta del archivo JSON de configuración.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Detecta y registra, pero no modifica iptables.",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Valida la configuración y termina.",
    )
    parser.add_argument(
        "--list-blocks",
        action="store_true",
        help="Muestra los bloqueos persistidos.",
    )
    parser.add_argument(
        "--unblock",
        metavar="IP",
        help="Elimina las reglas administradas para una IP.",
    )
    parser.add_argument(
        "--flush-blocks",
        action="store_true",
        help="Elimina todas las reglas de la cadena administrada.",
    )
    return parser

def main() -> int:
    """
    Punto de entrada de la aplicación. Configura el nivel de logs, analiza los argumentos del CLI,
    e invoca la acción solicitada por el usuario (verificar configuración, limpiar reglas, o iniciar el monitor).
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(threadName)s %(message)s",
    )
    args = build_parser().parse_args()

    try:
        config = load_config(args.config)
        if args.dry_run:
            config["dry_run"] = True
        validate_config(config)

        if args.check_config:
            print("Configuración válida.")
            print(json.dumps(config, indent=2, ensure_ascii=False))
            return 0

        if args.list_blocks or args.unblock or args.flush_blocks:
            firewall = Firewall(config)
            if args.list_blocks:
                firewall.print_blocks()
            if args.unblock:
                removed = firewall.unblock(args.unblock)
                print(f"Reglas eliminadas para {args.unblock}: {removed}")
            if args.flush_blocks:
                firewall.flush()
                print("Todos los bloqueos administrados fueron eliminados.")
            return 0

        return run_monitor(config)

    except KeyboardInterrupt:
        return 130
    except Exception as error:
        logging.exception("Fallo fatal: %s", error)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
