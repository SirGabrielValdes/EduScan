"""Inventario de puertos y servicios de un equipo.

Parte del *motor*. Dada una dirección IP, comprueba qué puertos TCP están
abiertos y les asigna un nombre de servicio conocido. Es no intrusivo: solo
intenta abrir la conexión ("¿este puerto acepta conexiones?") y la cierra de
inmediato. No envía datos, no autentica, no explota nada.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

# Puertos TCP habituales en una red escolar y el servicio que suelen indicar.
# La lista se mantiene corta a propósito: cubre lo relevante para un informe a
# directivos sin volver el escaneo lento ni ruidoso.
PUERTOS_COMUNES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP (web)",
    110: "POP3",
    139: "NetBIOS/SMB",
    143: "IMAP",
    443: "HTTPS (web segura)",
    445: "SMB (compartir archivos)",
    631: "IPP (impresora)",
    993: "IMAPS",
    995: "POP3S",
    1433: "SQL Server",
    3306: "MySQL",
    3389: "Escritorio remoto (RDP)",
    5432: "PostgreSQL",
    5900: "VNC (control remoto)",
    8080: "HTTP alternativo",
    8443: "HTTPS alternativo",
    9100: "Impresora (RAW/JetDirect)",
}

# Segundos de espera al intentar conectar a un puerto, segun la intensidad.
TIMEOUT = {
    "suave": 1.0,
    "normal": 0.5,
}

# Conexiones simultaneas por equipo, segun la intensidad.
CONCURRENCIA = {
    "suave": 20,
    "normal": 60,
}


@dataclass(frozen=True)
class Servicio:
    """Un puerto abierto en un equipo y el servicio que representa."""

    puerto: int
    nombre: str


def _puerto_abierto(ip: str, puerto: int, timeout: float) -> bool:
    """Devuelve True si se puede abrir una conexion TCP al puerto."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # connect_ex devuelve 0 si la conexion tuvo exito (puerto abierto).
        return sock.connect_ex((ip, puerto)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def escanear_puertos(
    ip: str,
    puertos: dict[int, str] | None = None,
    intensidad: str = "suave",
) -> list[Servicio]:
    """Inventaria los puertos abiertos de un equipo.

    Args:
        ip: dirección del equipo.
        puertos: mapa {puerto: nombre}. Por defecto, ``PUERTOS_COMUNES``.
        intensidad: "suave" o "normal"; ajusta espera y paralelismo.

    Returns:
        Lista de :class:`Servicio` abiertos, ordenada por número de puerto.
    """
    puertos = puertos or PUERTOS_COMUNES
    timeout = TIMEOUT.get(intensidad, TIMEOUT["suave"])
    trabajadores = CONCURRENCIA.get(intensidad, CONCURRENCIA["suave"])

    numeros = list(puertos)
    with ThreadPoolExecutor(max_workers=trabajadores) as executor:
        abiertos = list(
            executor.map(lambda p: _puerto_abierto(ip, p, timeout), numeros)
        )

    servicios = [
        Servicio(puerto=puerto, nombre=puertos[puerto])
        for puerto, esta_abierto in zip(numeros, abiertos)
        if esta_abierto
    ]
    servicios.sort(key=lambda s: s.puerto)
    return servicios


def inventariar_equipos(
    ips: list[str],
    puertos: dict[int, str] | None = None,
    intensidad: str = "suave",
) -> dict[str, list[Servicio]]:
    """Inventaria los puertos abiertos de varios equipos.

    Reutilizable por la CLI de hoy y por una futura interfaz web.

    Returns:
        Diccionario {ip: lista de servicios abiertos}.
    """
    return {
        ip: escanear_puertos(ip, puertos=puertos, intensidad=intensidad)
        for ip in ips
    }
