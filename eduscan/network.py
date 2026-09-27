"""Utilidades de red: detección de la red local.

Parte del *motor*. Sin efectos de interfaz (no imprime, no pregunta). Detecta en
qué red está la máquina que ejecuta EduScan, para poder proponerla al usuario.
"""

from __future__ import annotations

import ipaddress
import socket

# Tamaño de prefijo asumido por defecto al detectar la red local. /24 es el más
# común en redes pequeñas (hasta 254 equipos), típico de un colegio. El usuario
# confirma la red detectada antes de escanear, así que esta suposición es segura.
PREFIJO_POR_DEFECTO = 24


class RedError(Exception):
    """No se pudo determinar la red local."""


def detectar_ip_local() -> str:
    """Devuelve la dirección IPv4 local de la máquina.

    Usa el truco de abrir un socket UDP "hacia afuera": no envía datos ni
    requiere conexión real a Internet, solo hace que el sistema operativo elija
    la interfaz de salida y así podemos leer su IP. Es multiplataforma y no
    necesita privilegios.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # La IP de destino no importa; no se envía tráfico. 8.8.8.8 es solo un
        # ancla habitual para que el SO seleccione la interfaz por defecto.
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError as exc:
        raise RedError(
            "No se pudo determinar la IP local. ¿La máquina está conectada a "
            "la red del colegio?"
        ) from exc
    finally:
        sock.close()


def detectar_red_local(prefijo: int = PREFIJO_POR_DEFECTO) -> ipaddress.IPv4Network:
    """Detecta la red local a partir de la IP de la máquina.

    Args:
        prefijo: tamaño del prefijo de red (por defecto /24).

    Returns:
        La red local como :class:`ipaddress.IPv4Network`.

    Raises:
        RedError: si no se puede determinar la IP local o el prefijo es inválido.
    """
    if not 0 < prefijo <= 32:
        raise RedError(f"Prefijo de red inválido: /{prefijo}")

    ip = detectar_ip_local()
    try:
        return ipaddress.ip_network(f"{ip}/{prefijo}", strict=False)
    except ValueError as exc:  # pragma: no cover - defensivo
        raise RedError(f"No se pudo construir la red local: {exc}") from exc
