"""Interfaz de línea de comandos de EduScan.

Esta es una *capa de interfaz*: se encarga de leer argumentos, llamar al motor
(``eduscan.config``, y en el futuro los módulos de escaneo) y mostrar resultados.
La lógica real vive en el motor, para que mañana una app web pueda reutilizarla.
"""

from __future__ import annotations

import argparse
import sys

from eduscan import __version__
from eduscan.config import Config, ConfigError, cargar_config


def _cmd_validate(args: argparse.Namespace) -> int:
    """Valida el archivo de configuración y muestra un resumen."""
    try:
        config = cargar_config(args.config)
    except ConfigError as exc:
        print(f"❌ Configuración inválida: {exc}", file=sys.stderr)
        return 1

    _mostrar_resumen(config)
    print("\n✅ Configuración válida.")
    return 0


def _mostrar_resumen(config: Config) -> None:
    print("Resumen de la configuración de EduScan")
    print("=" * 40)
    print(f"Institución : {config.autorizacion.institucion}")
    print(f"Autoriza    : {config.autorizacion.autoriza}")
    print(f"Responsable : {config.autorizacion.responsable}")
    print(f"Intensidad  : {config.intensidad}")
    print("Subredes autorizadas:")
    for red in config.subredes:
        print(f"  - {red}")
    print("Chequeos activados:")
    for nombre, activo in config.chequeos.items():
        estado = "sí" if activo else "no"
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
        help="Valida el archivo de configuración sin escanear la red.",
    )
    p_validate.add_argument(
        "--config",
        default="config.yaml",
        help="Ruta al archivo de configuración (por defecto: config.yaml).",
    )
    p_validate.set_defaults(func=_cmd_validate)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
