#!/usr/bin/env bash
set -euo pipefail

# Verificar que el instalador se ejecute con privilegios de administrador (root)
if [[ "${EUID}" -ne 0 ]]; then
  echo "Ejecute este instalador con sudo."
  exit 1
fi

# Validar que las dependencias necesarias estén instaladas
command -v python3 >/dev/null || {
  echo "No se encontró python3. Instale: sudo apt install -y python3"
  exit 1
}

command -v iptables >/dev/null || {
  echo "No se encontró iptables. Instale: sudo apt install -y iptables"
  exit 1
}

# Obtener la ruta absoluta desde donde se ejecuta este script
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Crear las carpetas necesarias en el sistema con los permisos adecuados
install -d -m 0755 /opt/attack-detector
install -d -m 0755 /etc/attack-detector
install -d -m 0755 /var/log/attack-detector
install -d -m 0755 /var/lib/attack-detector

# Copiar el código fuente, la documentación y el archivo de servicio a sus ubicaciones finales
install -m 0755 "${SOURCE_DIR}/src/attack_detector.py" /opt/attack-detector/attack_detector.py
install -m 0644 "${SOURCE_DIR}/README.md" /opt/attack-detector/README.md
install -m 0644 "${SOURCE_DIR}/service/attack-detector.service" /etc/systemd/system/attack-detector.service

# Configurar el archivo JSON principal, respetando si ya existe uno previo para no sobrescribirlo
if [[ ! -f /etc/attack-detector/config.json ]]; then
  install -m 0644 "${SOURCE_DIR}/config/config.example.json" /etc/attack-detector/config.json
  echo "Configuración creada en /etc/attack-detector/config.json"
else
  echo "Se conservó la configuración existente."
fi

# Inicializar el archivo de eventos (logs de ataques) con permisos restringidos
touch /var/log/attack-detector/events.jsonl
chmod 0640 /var/log/attack-detector/events.jsonl

# Validar que la configuración sea correcta antes de encender el servicio
/usr/bin/python3 /opt/attack-detector/attack_detector.py \
  --config /etc/attack-detector/config.json \
  --check-config >/dev/null

# Recargar los demonios de systemd y habilitar/iniciar el servicio inmediatamente
systemctl daemon-reload
systemctl enable --now attack-detector.service

echo
echo "Instalación terminada."
echo "Estado: sudo systemctl status attack-detector"
echo "Logs:   sudo journalctl -u attack-detector -f"
echo "Reglas: sudo iptables -L ATTACK_DETECTOR -n --line-numbers"
