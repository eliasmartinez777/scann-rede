
# 🔍 Network Scanner 

Herramienta avanzada para escanear redes, detectar hosts activos, puertos abiertos y sistemas operativos.

## 🚀 Características Principales
- 🌐 Escaneo de redes (`192.168.1.0/24` o rangos personalizados)
- 🖥️ Detección de sistemas operativos mediante:
  - Análisis de TTL (Windows/Linux/Cisco)
  - Banners de servicios (SSH, HTTP, SMB)
- 📂 Exportación de resultados en formatos:
  - JSON (estructurado)
  - TXT (legible)
- 💻 Múltiples modos de uso:
  - Interfaz interactiva con menú
  - Línea de comandos para automatización

## 📦 Instalación

### Requisitos previos

- Python 3.6 o superior
- Librerías necesarias: `scapy`, `pyinstaller`

### Pasos de instalación

```bash
# Instalar dependencias
pip install scapy pyinstaller

# Crear ejecutable (Windows)
pyinstaller --onefile --icon=network.ico scanner.py
```

## 🧭 Menú Principal

- Escanear red completa → Ej: `192.168.1.0/24`
- Escanear puertos específicos → Ej: `22, 80, 443`
- Escaneo rápido (puertos comunes: 21-23, 80, 443, 3389)
- Ver resultados
- Guardar reportes (JSON/TXT)

## 👥 Equipo

| Integrante         | Rol                   |
|--------------------|------------------------|
| Elias Martinez     | Desarrollo Principal   |
| Ivan Orostegui     | Documentación          |
| Fernando           | Pruebas y Validación   |
