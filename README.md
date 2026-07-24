# Detector de ataques — Laboratorio 08

Proyecto defensivo para un entorno controlado. La herramienta sigue los logs
del servidor en tiempo real, detecta comportamientos definidos y crea reglas
en una cadena propia de `iptables`.

## Qué detecta

1. **SQLMap en Apache** por el `User-Agent` que contiene `sqlmap`.
2. **Patrones de SQL Injection** visibles en la URL, por ejemplo `UNION SELECT`,
   `OR 1=1`, `information_schema`, `sleep(...)` y otros.
3. **Hydra contra el formulario web**, por `User-Agent` cuando esté presente.
4. **Fuerza bruta HTTP POST**, por muchos `POST` fallidos al login en una
   ventana corta.
5. **Fuerza bruta FTP**, por muchas líneas `FAIL LOGIN` en `vsftpd.log`.
6. **Fuerza bruta SSH**, disponible pero deshabilitada por defecto.

## Diseño de seguridad

`block_scope` está configurado como `service`. Así, un ataque web bloquea
solamente los puertos 80/443 y un ataque FTP bloquea el 21. Esto reduce el
riesgo de perder la sesión SSH durante la demostración.

Puede cambiarlo a `"all"` para bloquear todo el tráfico de la IP, pero no es
recomendable si la máquina atacante comparte la misma IP pública que la
máquina desde la que administra EC2.

La cadena administrada es:

```bash
ATTACK_DETECTOR
```

La herramienta inserta un salto desde `INPUT` y registra sus eventos en:

```bash
/var/log/attack-detector/events.jsonl
```

## Instalación en Ubuntu 24.04

Copie la carpeta al servidor y ejecute:

```bash
sudo apt update
sudo apt install -y python3 iptables unzip
cd attack-detector-lab
sudo ./install.sh
```

Antes o después de instalar, revise:

```bash
sudo nano /etc/attack-detector/config.json
```

No agregue la IP atacante a `allowlist`. Agregue únicamente direcciones que
nunca deban bloquearse. SSH está deshabilitado por defecto para evitar un
bloqueo accidental del acceso administrativo.

## Comandos del servicio

```bash
sudo systemctl start attack-detector
sudo systemctl restart attack-detector
sudo systemctl stop attack-detector
sudo systemctl status attack-detector
```

Para activarlo en cada arranque:

```bash
sudo systemctl enable attack-detector
```

Para ver detecciones en vivo:

```bash
sudo journalctl -u attack-detector -f
```

## Verificación previa

```bash
sudo /usr/bin/python3 /opt/attack-detector/attack_detector.py \
  --config /etc/attack-detector/config.json \
  --check-config
```

Compruebe que los logs existen y reciben eventos:

```bash
sudo tail -f /var/log/apache2/access.log
sudo tail -f /var/log/vsftpd.log
sudo tail -f /var/log/auth.log
```

## Demostración recomendada para el video

Abra tres terminales:

**Terminal 1 — servicio y eventos**

```bash
sudo systemctl status attack-detector
sudo journalctl -u attack-detector -f
```

**Terminal 2 — reglas de firewall**

```bash
watch -n 1 'sudo iptables -L ATTACK_DETECTOR -n --line-numbers'
```

**Terminal 3 — máquina atacante**

Ejecute el comando de SQLMap o Hydra indicado por el laboratorio contra la
instancia propia. Cuando el umbral se cumpla, en Terminal 1 aparecerá
`BLOCKED` y en Terminal 2 aparecerá una regla `DROP`.

Después compruebe que nuevas conexiones al servicio atacado fallan.

## Administrar bloqueos

Listar el estado persistido:

```bash
sudo /usr/bin/python3 /opt/attack-detector/attack_detector.py \
  --config /etc/attack-detector/config.json \
  --list-blocks
```

Desbloquear una IP:

```bash
sudo /usr/bin/python3 /opt/attack-detector/attack_detector.py \
  --config /etc/attack-detector/config.json \
  --unblock 203.0.113.10
```

Vaciar todos los bloqueos del laboratorio:

```bash
sudo /usr/bin/python3 /opt/attack-detector/attack_detector.py \
  --config /etc/attack-detector/config.json \
  --flush-blocks
```

## Probar sin tocar iptables

Detenga temporalmente el servicio y ejecute:

```bash
sudo systemctl stop attack-detector
sudo /usr/bin/python3 /opt/attack-detector/attack_detector.py \
  --config /etc/attack-detector/config.json \
  --dry-run
```

En ese modo detecta y escribe eventos, pero no agrega reglas.

## Pruebas unitarias

Desde la carpeta del proyecto:

```bash
python3 -m unittest -v tests/test_detector.py
```

## Ajustes que posiblemente deba cambiar

- `web_bruteforce.paths`: debe coincidir con la ruta real del login.
- `failure_statuses`: el laboratorio indica que los intentos fallidos pueden
  verse como `200`, mientras que un login exitoso puede devolver `302`.
- `threshold` y `window_seconds`: reduzca los valores para una demostración
  más rápida o auméntelos para disminuir falsos positivos.
- Rutas de logs: confirme las rutas reales en su instancia.
