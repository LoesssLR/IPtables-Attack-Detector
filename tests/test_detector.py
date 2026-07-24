#!/usr/bin/env python3
import copy
import unittest

from src.attack_detector import DEFAULT_CONFIG, DetectorEngine

class Recorder:
    """Clase auxiliar para grabar los eventos generados por el motor de detección durante las pruebas."""
    def __init__(self):
        self.events = []

    def __call__(self, **event):
        self.events.append(event)
        return True

class DetectorTests(unittest.TestCase):
    """Suite de pruebas unitarias para validar las reglas de detección del motor (DetectorEngine)."""
    
    def setUp(self):
        """Prepara el entorno de prueba creando una nueva instancia del motor con la configuración base."""
        self.config = copy.deepcopy(DEFAULT_CONFIG)
        self.recorder = Recorder()
        self.engine = DetectorEngine(self.config, self.recorder)

    def test_detects_sqlmap_user_agent(self):
        """Verifica que una petición HTTP que incluya 'sqlmap' en su User-Agent sea detectada inmediatamente."""
        line = (
            '198.51.100.10 - - [23/Jul/2026:13:00:00 -0600] '
            '"GET /sistema/ver_producto.php?id=1 HTTP/1.1" 200 123 "-" '
            '"sqlmap/1.9#stable (https://sqlmap.org)"'
        )
        self.engine.process("apache", line)
        self.assertEqual(len(self.recorder.events), 1)
        self.assertEqual(self.recorder.events[0]["detector"], "sqlmap_user_agent")

    def test_detects_web_bruteforce_after_threshold(self):
        """Verifica que múltiples intentos HTTP POST (fuerza bruta web) superen el umbral configurado (8 intentos)."""
        for second in range(8):
            line = (
                f'198.51.100.20 - - [23/Jul/2026:13:00:{second:02d} -0600] '
                '"POST /sistema/index.php HTTP/1.1" 200 456 "-" "Mozilla/5.0"'
            )
            self.engine.process("apache", line)
        self.assertTrue(
            any(event["detector"] == "web_bruteforce" for event in self.recorder.events)
        )

    def test_detects_ftp_bruteforce_after_threshold(self):
        """Verifica que múltiples fallos de login en FTP se detecten si superan el umbral (6 intentos)."""
        for _ in range(6):
            self.engine.process(
                "vsftpd",
                'Thu Jul 23 13:00:00 2026 [pid 321] [usuario] '
                'FAIL LOGIN: Client "198.51.100.30"',
            )
        self.assertTrue(
            any(event["detector"] == "ftp_bruteforce" for event in self.recorder.events)
        )

    def test_allowlist_is_respected(self):
        """Asegura que IPs en la allowlist (ej. localhost) puedan hacer cualquier petición sin ser bloqueadas."""
        line = (
            '127.0.0.1 - - [23/Jul/2026:13:00:00 -0600] '
            '"GET /?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 123 "-" '
            '"sqlmap/1.9"'
        )
        self.engine.process("apache", line)
        self.assertEqual(self.recorder.events, [])

if __name__ == "__main__":
    unittest.main(verbosity=2)