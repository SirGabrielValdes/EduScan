"""Interfaz de línea de comandos de EduScan.

Esta es una *capa de interfaz*: lee argumentos, llama al motor
(``eduscan.config``, ``eduscan.network``, ``eduscan.discovery``) y muestra
resultados. La lógica real vive en el motor, para que mañana una app web pueda
reutilizarla.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys

from eduscan import __version__
from eduscan.config import Config, ConfigError, cargar_config
from eduscan.discovery import DescubrimientoError, contar_hosts, descubrir_equipos
from eduscan.network import RedError, detectar_red_local


def _cmd_validate(args: argparse.Namespace) -> int:
    """Valida el archivo de configuración y muestra un resumen."""
    try:
        config = cargar_config(args.config)
    except ConfigError as exc:
        print(f"Configuracion invalida: {exc}", file=sys.stderr)
        return 1

    _mostrar_resumen(config)
    print("\nConfiguracion valida.")
    return 0


def _cmd_discover(args: argparse.Namespace) -> int:
    """Descubre los equipos activos en la red (auto-detectada o indicada)."""
    try:
        if args.red:
            red = ipaddress.ip_network(args.red, strict=False)
        else:
            red = detectar_red_local(prefijo=args.prefijo)
    except (RedError, ValueError) as exc:
        print(f"No se pudo determinar la red: {exc}", file=sys.stderr)
        return 1

    total = contar_hosts(red)
    print(f"Red detectada: {red} ({total} direcciones posibles)")

    if not _confirmar_autorizacion(red, asumir_si=args.si):
        print("Descubrimiento cancelado.")
        return 0

    print(f"Buscando equipos activos (intensidad: {args.intensidad})...")
    try:
        equipos = descubrir_equipos(red, intensidad=args.intensidad)
    except DescubrimientoError as exc:
        print(f"No se pudo completar el descubrimiento: {exc}", file=sys.stderr)
        return 1

    _mostrar_equipos(equipos)
    return 0


def _confirmar_autorizacion(red: ipaddress.IPv4Network, asumir_si: bool) -> bool:
    """Pide confirmacion explicita de autorizacion antes de escanear.

    Es el candado interactivo equivalente al de la configuracion: nadie escanea
    una red sin declarar que tiene permiso para hacerlo.
    """
    if asumir_si:
        return True

    print(
        "\nEduScan solo debe usarse en redes que tienes autorizacion para "
        "analizar (ver SCOPE.md)."
    )
    respuesta = input(f"Confirmas que estas autorizado a escanear {red}? [si/no]: ")
    return respuesta.strip().lower() in ("si", "s", "sí", "yes", "y")


def _mostrar_equipos(equipos: list) -> None:
    if not equipos:
        print("No se encontraron equipos activos.")
        return

    print(f"\nEquipos activos encontrados: {len(equipos)}")
    print("-" * 40)
    for equipo in equipos:
        nombre = equipo.hostname or "(sin nombre)"
        print(f"  {equipo.ip:<16} {nombre}")


def _mostrar_resumen(config: Config) -> None:
    print("Resumen de la configuracion de EduScan")
    print("=" * 40)
    print(f"Institucion : {config.autorizacion.institucion}")
    print(f"Autoriza    : {config.autorizacion.autoriza}")
    print(f"Responsable : {config.autorizacion.responsable}")
    print(f"Intensidad  : {config.intensidad}")
    print("Subredes autorizadas:")
    for red in config.subredes:
        print(f"  - {red}")
    print("Chequeos activados:")
    for nombre, activo in config.chequeos.items():
        estado = "si" if activo else "no"
        print(f"  - {nombre}: {estado}")


def construir_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eduscan",
        description=(
            "Analiza la red de un colegio en un entorno autorizado y genera "
            "un informe para directivos."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"EduScan {__version__}",
    )

    subparsers = parser.add_subparsers(dest="comando", required=True)

    p_validate = subparsers.add_parser(
        "validate",
        help="Valida el archivo de configuracion sin escanear la red.",
    )
    p_validate.add_argument(
        "--config",
        default="config.yaml",
        help="Ruta al archivo de configuracion (por defecto: config.yaml).",
    )
    p_validate.set_defaults(func=_cmd_validate)

    p_discover = subparsers.add_parser(
        "discover",
        help="Descubre los equipos activos en la red local.",
    )
    p_discover.add_argument(
        "--red",
        default=None,
        help="Red a escanear en notacion CIDR. Si se omite, se auto-detecta.",
    )
    p_discover.add_argument(
        "--prefijo",
        type=int,
        default=24,
        help="Tamano de prefijo al auto-detectar (por defecto: 24).",
    )
    p_discover.add_argument(
        "--intensidad",
        default="suave",
        choices=("suave", "normal"),
        help="Intensidad del escaneo (por defecto: suave).",
    )
    p_discover.add_argument(
        "--si",
        action="store_true",
        help="Asume 'si' en la confirmacion de autorizacion (uso no interactivo).",
    )
    p_discover.set_defaults(func=_cmd_discover)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
