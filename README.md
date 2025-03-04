# OS Detector (TTL-Based)

OS Detector es una herramienta de pentesting que permite identificar el sistema operativo de un host remoto basándose en el TTL (Time To Live) de la respuesta a una solicitud ICMP.

## 📌 Características
- Detección de sistemas operativos basándose en valores TTL comunes.
- Normalización del TTL para mejorar la precisión.
- Soporte para modo detallado (`-v`) con información adicional.
- Manejo de errores y validación de direcciones IP.
- Mensajes en color para mejorar la visualización de resultados.

## 📥 Instalación
Para usar esta herramienta, necesitas tener instalado Python 3 y la librería `scapy`.

```bash
pip install scapy colorama
```

## 🚀 Uso
Ejecuta el script con permisos de administrador para enviar paquetes ICMP:

```bash
sudo python3 os_detector.py <IP>
```

Opciones disponibles:

```bash
-h, --help       Muestra la ayuda del script.
-v, --verbose    Activa el modo detallado para ver información adicional.
```

### 🔹 Ejemplo de uso:
```bash
sudo python3 os_detector.py 192.168.1.1
```

Salida esperada:
```
[INFO] Enviando solicitud ICMP a 192.168.1.1...
[INFO] TTL recibido: 64
[DEBUG] TTL normalizado: 64
[INFO] Sistemas operativos posibles:
 - Linux
 - FreeBSD
 - Red Hat 9
```

## 🔧 Requisitos
- Python 3.x
- Permisos de administrador (necesarios para enviar paquetes ICMP)
- Librerías: `scapy`, `colorama`

## ⚠️ Advertencia
El uso de esta herramienta sin autorización en redes ajenas puede ser ilegal. Asegúrate de tener permiso antes de escanear cualquier sistema.
