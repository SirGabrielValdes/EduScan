"""Descubrimiento de equipos activos en una red.

Parte del *motor*. Dada una red, averigua qué equipos responden ("están vivos")
usando ping, de forma no intrusiva. No abre puertos ni prueba credenciales: solo
pregunta "¿estás ahí?". El inventario de servicios es un paso posterior.
"""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

# Cantidad máxima de direcciones que aceptamos escanear sin una confirmación
# explícita de tamaño. Evita que una red mal configurada dispare un escaneo
# gigantesco por accidente. Un /24 (254 hosts) queda holgadamente por debajo.
MAX_HOSTS_POR_DEFECTO = 1024

# Cantidad de pings simultáneos según la intensidad. "suave" es amable con la
# red del colegio en horario de clases.
CONCURRENCIA = {
    "suave": 16,
    "normal": 64,
}


class DescubrimientoError(Exception):
    """No se pudo realizar el descubrimiento (p. ej. red demasiado grande)."""


@dataclass(frozen=True)
class Equipo:
    """Un equipo que respondió durante el descubrimiento."""

    ip: str
    hostname: str | None = None


def contar_hosts(red: ipaddress.IPv4Network) -> int:
    """Número de direcciones asignables a equipos en la red."""
    # num_addresses incluye red y broadcast; hosts() los excluye en /24 y menores.
    return sum(1 for _ in red.hosts())


def _comando_ping(ip: str) -> list[str]:
    """Construye el comando de ping de un solo intento para el SO actual."""
    if platform.system().lower() == "windows":
        # -n 1: un eco; -w 1000: espera 1000 ms.
        return ["ping", "-n", "1", "-w", "1000", ip]
    # Linux/Mac: -c 1: un eco; -W 1: espera 1 s.
    return ["ping", "-c", "1", "-W", "1", ip]


def _esta_vivo(ip: str) -> bool:
    """Devuelve True si el equipo responde al ping."""
    try:
        resultado = subprocess.run(
            _comando_ping(ip),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    return resultado.returncode == 0


def _resolver_hostname(ip: str) -> str | None:
    """Intenta resolver el nombre del equipo (mejor esfuerzo)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def descubrir_equipos(
    red: ipaddress.IPv4Network,
    intensidad: str = "suave",
    max_hosts: int = MAX_HOSTS_POR_DEFECTO,
) -> list[Equipo]:
    """Descubre los equipos activos en una red.

    Args:
        red: la red a explorar.
        intensidad: "suave" o "normal"; controla cuántos pings van en paralelo.
        max_hosts: tope de direcciones a explorar sin confirmación explícita.

    Returns:
        Lista de :class:`Equipo` que respondieron, ordenada por IP.

    Raises:
        DescubrimientoError: si la red supera ``max_hosts``.
    """
    total = contar_hosts(red)
    if total > max_hosts:
        raise DescubrimientoError(
            f"La red {red} tiene {total} direcciones, por encima del límite de "
            f"{max_hosts}. Reduce el alcance o ajusta el límite explícitamente."
        )

    trabajadores = CONCURRENCIA.get(intensidad, CONCURRENCIA["suave"])
    direcciones = [str(ip) for ip in red.hosts()]

    with ThreadPoolExecutor(max_workers=trabajadores) as executor:
        vivos = list(executor.map(_esta_vivo, direcciones))

    equipos = [
        Equipo(ip=ip, hostname=_resolver_hostname(ip))
        for ip, vivo in zip(direcciones, vivos)
        if vivo
    ]
    equipos.sort(key=lambda e: ipaddress.ip_address(e.ip))
    return equipos


def descubrir_en_redes(
    redes: list[ipaddress.IPv4Network],
    intensidad: str = "suave",
    max_hosts: int = MAX_HOSTS_POR_DEFECTO,
) -> dict[str, list[Equipo]]:
    """Descubre equipos activos en varias redes (p. ej. varias salas).

    Es la base del modelo "central": recorre una lista de subredes autorizadas
    y devuelve los equipos encontrados en cada una. Reutilizable por la CLI de
    hoy y por una futura interfaz web.

    Args:
        redes: lista de redes a explorar.
        intensidad: "suave" o "normal".
        max_hosts: tope de direcciones por red.

    Returns:
        Diccionario {red (str): lista de equipos}, en el orden recibido.

    Raises:
        DescubrimientoError: si alguna red supera ``max_hosts``.
    """
    resultados: dict[str, list[Equipo]] = {}
    for red in redes:
        resultados[str(red)] = descubrir_equipos(
            red, intensidad=intensidad, max_hosts=max_hosts
        )
    return resultados
