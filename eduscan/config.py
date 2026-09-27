"""Carga y validación de la configuración de EduScan.

Este módulo es parte del *motor*: no imprime nada ni interactúa con el usuario.
Solo lee un archivo YAML, lo valida y devuelve un objeto de configuración, o
lanza ``ConfigError`` describiendo qué está mal. Así puede ser reutilizado tanto
por la línea de comandos de hoy como por una futura interfaz web.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Intensidades de escaneo permitidas.
INTENSIDADES_VALIDAS = ("suave", "normal")

# Chequeos reconocidos por EduScan. La configuración puede activarlos o
# desactivarlos; cualquier clave desconocida se considera un error.
CHEQUEOS_CONOCIDOS = (
    "descubrimiento_equipos",
    "inventario_servicios",
    "configuraciones_riesgo",
    "credenciales_por_defecto",
)


class ConfigError(Exception):
    """La configuración es inválida. El mensaje explica el motivo."""


@dataclass(frozen=True)
class Autorizacion:
    """Marco de autorización bajo el que opera EduScan."""

    institucion: str
    autoriza: str
    responsable: str
    autorizado: bool


@dataclass(frozen=True)
class Config:
    """Configuración validada de una ejecución de EduScan."""

    autorizacion: Autorizacion
    subredes: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    intensidad: str
    chequeos: dict[str, bool] = field(default_factory=dict)


def cargar_config(ruta: str | Path) -> Config:
    """Lee y valida un archivo de configuración YAML.

    Args:
        ruta: ruta al archivo ``config.yaml``.

    Returns:
        Un objeto :class:`Config` validado.

    Raises:
        ConfigError: si el archivo no existe, no es YAML válido, o su contenido
            no cumple las reglas de EduScan.
    """
    ruta = Path(ruta)
    if not ruta.exists():
        raise ConfigError(f"No se encontró el archivo de configuración: {ruta}")

    try:
        texto = ruta.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"No se pudo leer {ruta}: {exc}") from exc

    try:
        datos = yaml.safe_load(texto)
    except yaml.YAMLError as exc:
        raise ConfigError(f"El archivo no es YAML válido: {exc}") from exc

    return validar_config(datos)


def validar_config(datos: Any) -> Config:
    """Valida un diccionario de configuración ya parseado.

    Se separa de :func:`cargar_config` para poder validar configuraciones que
    vengan de otras fuentes (por ejemplo, un formulario web en el futuro).
    """
    if not isinstance(datos, dict):
        raise ConfigError("La configuración debe ser un mapa (clave: valor).")

    autorizacion = _validar_autorizacion(datos.get("autorizacion"))
    subredes = _validar_subredes(datos.get("subredes"))
    intensidad = _validar_intensidad(datos.get("intensidad", "suave"))
    chequeos = _validar_chequeos(datos.get("chequeos"))

    return Config(
        autorizacion=autorizacion,
        subredes=subredes,
        intensidad=intensidad,
        chequeos=chequeos,
    )


def _validar_autorizacion(valor: Any) -> Autorizacion:
    if not isinstance(valor, dict):
        raise ConfigError("Falta la sección 'autorizacion' o no es un mapa.")

    faltantes = [
        campo
        for campo in ("institucion", "autoriza", "responsable")
        if not str(valor.get(campo, "")).strip()
    ]
    if faltantes:
        raise ConfigError(
            "La sección 'autorizacion' requiere los campos: "
            + ", ".join(faltantes)
        )

    autorizado = valor.get("autorizado", False)
    if not isinstance(autorizado, bool):
        raise ConfigError("'autorizacion.autorizado' debe ser true o false.")
    if not autorizado:
        raise ConfigError(
            "El escaneo no está autorizado. Ajusta 'autorizacion.autorizado' a "
            "true solo cuando tengas el permiso por escrito (ver SCOPE.md)."
        )

    return Autorizacion(
        institucion=str(valor["institucion"]).strip(),
        autoriza=str(valor["autoriza"]).strip(),
        responsable=str(valor["responsable"]).strip(),
        autorizado=True,
    )


def _validar_subredes(
    valor: Any,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    if not isinstance(valor, list) or not valor:
        raise ConfigError(
            "Debes indicar al menos una subred en 'subredes' (notación CIDR)."
        )

    subredes = []
    for item in valor:
        try:
            red = ipaddress.ip_network(str(item), strict=False)
        except ValueError as exc:
            raise ConfigError(f"Subred inválida '{item}': {exc}") from exc
        subredes.append(red)
    return subredes


def _validar_intensidad(valor: Any) -> str:
    intensidad = str(valor).strip().lower()
    if intensidad not in INTENSIDADES_VALIDAS:
        raise ConfigError(
            f"'intensidad' debe ser una de {INTENSIDADES_VALIDAS}, "
            f"no '{valor}'."
        )
    return intensidad


def _validar_chequeos(valor: Any) -> dict[str, bool]:
    if valor is None:
        # Si no se especifica, se activan todos los chequeos conocidos.
        return {nombre: True for nombre in CHEQUEOS_CONOCIDOS}

    if not isinstance(valor, dict):
        raise ConfigError("La sección 'chequeos' debe ser un mapa (clave: true/false).")

    desconocidos = [k for k in valor if k not in CHEQUEOS_CONOCIDOS]
    if desconocidos:
        raise ConfigError(
            "Chequeos desconocidos en 'chequeos': "
            + ", ".join(desconocidos)
            + f". Los válidos son: {', '.join(CHEQUEOS_CONOCIDOS)}."
        )

    chequeos = {nombre: True for nombre in CHEQUEOS_CONOCIDOS}
    for nombre, activo in valor.items():
        if not isinstance(activo, bool):
            raise ConfigError(f"'chequeos.{nombre}' debe ser true o false.")
        chequeos[nombre] = activo
    return chequeos
