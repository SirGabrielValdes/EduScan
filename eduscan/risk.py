"""Análisis de riesgo de los servicios expuestos.

Parte del *motor*. Toma la lista de puertos/servicios abiertos de un equipo y la
traduce a hallazgos entendibles: qué tan grave es, por qué, y qué hacer. También
marca (Opción A) los servicios que suelen venir con credenciales de fábrica, para
avisar sin probar contraseñas.

No explota nada: solo razona sobre lo que el inventario encontró.
"""

from __future__ import annotations

from dataclasses import dataclass

from eduscan.scanning import Servicio

# Niveles de riesgo, de mayor a menor, con un valor para poder compararlos.
NIVELES = {"ALTO": 3, "MEDIO": 2, "BAJO": 1, "INFO": 0}


@dataclass(frozen=True)
class Hallazgo:
    """Un riesgo detectado en un servicio expuesto."""

    puerto: int
    servicio: str
    nivel: str
    motivo: str
    recomendacion: str
    revisar_credenciales: bool = False


# Reglas de riesgo por puerto. Cada entrada explica el porqué en lenguaje simple
# y una recomendación accionable. 'cred' marca servicios que suelen traer
# credenciales de fábrica (Opción A: solo avisamos, no probamos contraseñas).
_REGLAS: dict[int, dict] = {
    23: {
        "nivel": "ALTO",
        "motivo": "Telnet envía las contraseñas sin cifrar; cualquiera en la red puede leerlas.",
        "recomendacion": "Desactiva Telnet y usa SSH en su lugar.",
        "cred": True,
    },
    3389: {
        "nivel": "ALTO",
        "motivo": "Escritorio remoto (RDP) expuesto es un blanco frecuente de ataques.",
        "recomendacion": "Limita el acceso por red o VPN y usa contraseñas fuertes.",
        "cred": True,
    },
    5900: {
        "nivel": "ALTO",
        "motivo": "VNC (control remoto) suele quedar sin cifrado o con contraseña débil.",
        "recomendacion": "Restringe el acceso y exige contraseña robusta o VPN.",
        "cred": True,
    },
    1433: {
        "nivel": "ALTO",
        "motivo": "Una base de datos (SQL Server) accesible desde la red es un riesgo alto.",
        "recomendacion": "Que solo la use el servidor que la necesita, no toda la red.",
        "cred": True,
    },
    21: {
        "nivel": "MEDIO",
        "motivo": "FTP transmite credenciales sin cifrar y a veces permite acceso anónimo.",
        "recomendacion": "Sustitúyelo por SFTP/HTTPS o restringe su uso.",
        "cred": True,
    },
    445: {
        "nivel": "MEDIO",
        "motivo": "Compartir archivos (SMB) ha sido vector de ransomware conocido.",
        "recomendacion": "Actualiza el sistema y limita quién puede acceder.",
    },
    554: {
        "nivel": "ALTO",
        "motivo": "Cámara IP (RTSP) expuesta; suele traer usuario/contraseña de fábrica.",
        "recomendacion": "Cambia las credenciales de la cámara y restringe su acceso por red.",
        "cred": True,
    },
    1883: {
        "nivel": "MEDIO",
        "motivo": "MQTT (IoT) suele quedar sin autenticación, exponiendo dispositivos.",
        "recomendacion": "Exige autenticación y limita el acceso al servicio.",
        "cred": True,
    },
    2323: {
        "nivel": "ALTO",
        "motivo": "Telnet (puerto alternativo) envía las contraseñas sin cifrar.",
        "recomendacion": "Desactívalo y usa SSH en su lugar.",
        "cred": True,
    },
    5985: {
        "nivel": "MEDIO",
        "motivo": "Gestión remota de Windows (WinRM) expuesta amplía la superficie de ataque.",
        "recomendacion": "Limita su acceso a administradores y por red de gestión.",
    },
    6379: {
        "nivel": "ALTO",
        "motivo": "Redis suele quedar accesible sin contraseña; cualquiera podría leer/borrar datos.",
        "recomendacion": "Exige contraseña y que solo lo use el servidor que lo necesita.",
        "cred": True,
    },
    27017: {
        "nivel": "ALTO",
        "motivo": "MongoDB expuesto ha filtrado datos por quedar sin autenticación.",
        "recomendacion": "Exige autenticación y restríngelo al servidor que lo usa.",
        "cred": True,
    },
    139: {
        "nivel": "MEDIO",
        "motivo": "NetBIOS/SMB antiguo amplía la superficie de ataque.",
        "recomendacion": "Desactívalo si no es imprescindible.",
    },
    3306: {
        "nivel": "MEDIO",
        "motivo": "Base de datos (MySQL) accesible desde la red.",
        "recomendacion": "Restríngela al servidor que la usa.",
        "cred": True,
    },
    5432: {
        "nivel": "MEDIO",
        "motivo": "Base de datos (PostgreSQL) accesible desde la red.",
        "recomendacion": "Restríngela al servidor que la usa.",
        "cred": True,
    },
    80: {
        "nivel": "MEDIO",
        "motivo": "Panel/servicio web sin cifrar (HTTP); credenciales viajan expuestas.",
        "recomendacion": "Usa HTTPS y revisa que no tenga la contraseña de fábrica.",
        "cred": True,
    },
    8080: {
        "nivel": "MEDIO",
        "motivo": "Panel web alternativo sin cifrar; frecuente en dispositivos de administración.",
        "recomendacion": "Usa HTTPS y cambia la contraseña por defecto.",
        "cred": True,
    },
    5000: {
        "nivel": "MEDIO",
        "motivo": "Panel/servicio web sin cifrar; frecuente en dispositivos y aplicaciones.",
        "recomendacion": "Usa HTTPS y revisa que no tenga la contraseña de fábrica.",
        "cred": True,
    },
    8000: {
        "nivel": "MEDIO",
        "motivo": "Panel/servicio web alternativo sin cifrar.",
        "recomendacion": "Usa HTTPS y cambia la contraseña por defecto.",
        "cred": True,
    },
    8888: {
        "nivel": "MEDIO",
        "motivo": "Panel/servicio web alternativo sin cifrar.",
        "recomendacion": "Usa HTTPS y cambia la contraseña por defecto.",
        "cred": True,
    },
    631: {
        "nivel": "MEDIO",
        "motivo": "Panel de impresora expuesto; suele traer credenciales de fábrica.",
        "recomendacion": "Cambia la contraseña de la impresora y limita su acceso.",
        "cred": True,
    },
    9100: {
        "nivel": "MEDIO",
        "motivo": "Impresora accesible directamente (RAW/JetDirect); puede imprimirse sin control.",
        "recomendacion": "Restringe el acceso a la impresora por red.",
        "cred": True,
    },
    22: {
        "nivel": "BAJO",
        "motivo": "SSH está cifrado, pero exponerlo amplía la superficie de ataque.",
        "recomendacion": "Restringe el acceso y revisa credenciales fuertes.",
        "cred": True,
    },
}

# Servicios cifrados o de infraestructura habitual: informativos por defecto.
_INFO = {
    25: "Correo (SMTP).",
    53: "Servicio DNS.",
    110: "Correo (POP3).",
    143: "Correo (IMAP).",
    443: "Web segura (HTTPS).",
    993: "Correo cifrado (IMAPS).",
    995: "Correo cifrado (POP3S).",
    8443: "Web segura alternativa (HTTPS).",
}


def analizar_servicios(servicios: list[Servicio]) -> list[Hallazgo]:
    """Convierte los servicios abiertos de un equipo en hallazgos de riesgo.

    El resultado se ordena de mayor a menor gravedad.
    """
    hallazgos: list[Hallazgo] = []
    for servicio in servicios:
        regla = _REGLAS.get(servicio.puerto)
        if regla is not None:
            hallazgos.append(
                Hallazgo(
                    puerto=servicio.puerto,
                    servicio=servicio.nombre,
                    nivel=regla["nivel"],
                    motivo=regla["motivo"],
                    recomendacion=regla["recomendacion"],
                    revisar_credenciales=regla.get("cred", False),
                )
            )
        else:
            motivo = _INFO.get(servicio.puerto, "Servicio expuesto en la red.")
            hallazgos.append(
                Hallazgo(
                    puerto=servicio.puerto,
                    servicio=servicio.nombre,
                    nivel="INFO",
                    motivo=motivo,
                    recomendacion="Confirma que este servicio debe estar accesible.",
                )
            )

    hallazgos.sort(key=lambda h: NIVELES[h.nivel], reverse=True)
    return hallazgos


def nivel_maximo(hallazgos: list[Hallazgo]) -> str:
    """Devuelve el nivel de riesgo más alto de una lista de hallazgos."""
    if not hallazgos:
        return "INFO"
    return max(hallazgos, key=lambda h: NIVELES[h.nivel]).nivel
