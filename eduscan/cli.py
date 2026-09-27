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
from datetime import date
from pathlib import Path

from eduscan import __version__
from eduscan.audit import auditar_redes
from eduscan.config import Config, ConfigError, cargar_config
from eduscan.discovery import (
    DescubrimientoError,
    contar_hosts,
    descubrir_en_redes,
    descubrir_equipos,
)
from eduscan.network import RedError, detectar_red_local
from eduscan.report import generar_html, generar_markdown


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
    """Descubre equipos activos: en varias salas (config) o en una red."""
    if args.config:
        return _discover_desde_config(args)
    return _discover_una_red(args)


def _discover_desde_config(args: argparse.Namespace) -> int:
    """Recorre todas las subredes autorizadas de un archivo de configuracion."""
    try:
        config = cargar_config(args.config)
    except ConfigError as exc:
        print(f"Configuracion invalida: {exc}", file=sys.stderr)
        return 1

    print(f"Institucion: {config.autorizacion.institucion}")
    print(f"Responsable: {config.autorizacion.responsable}")
    print(f"Subredes autorizadas: {len(config.subredes)}")
    print(f"Intensidad: {config.intensidad}\n")

    try:
        resultados = descubrir_en_redes(
            config.subredes, intensidad=config.intensidad
        )
    except DescubrimientoError as exc:
        print(f"No se pudo completar el descubrimiento: {exc}", file=sys.stderr)
        return 1

    total = 0
    for red, equipos in resultados.items():
        print(f"Red {red}:")
        _mostrar_equipos(equipos, sangria="  ")
        print()
        total += len(equipos)

    print(f"Total de equipos activos en todas las salas: {total}")
    return 0


def _discover_una_red(args: argparse.Namespace) -> int:
    """Descubre equipos en una sola red (auto-detectada o indicada)."""
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


def _resolver_objetivo(args: argparse.Namespace):
    """Determina redes/intensidad/datos segun --config, --red o auto-deteccion.

    Devuelve una tupla (codigo, redes, intensidad, institucion, responsable).
    Si 'codigo' no es None, el comando debe terminar devolviendo ese codigo.
    """
    if args.config:
        try:
            config = cargar_config(args.config)
        except ConfigError as exc:
            print(f"Configuracion invalida: {exc}", file=sys.stderr)
            return 1, [], "", "", ""
        return (
            None,
            config.subredes,
            config.intensidad,
            config.autorizacion.institucion,
            config.autorizacion.responsable,
        )

    try:
        if args.red:
            red = ipaddress.ip_network(args.red, strict=False)
        else:
            red = detectar_red_local(prefijo=args.prefijo)
    except (RedError, ValueError) as exc:
        print(f"No se pudo determinar la red: {exc}", file=sys.stderr)
        return 1, [], "", "", ""

    print(f"Red detectada: {red} ({contar_hosts(red)} direcciones posibles)")
    if not _confirmar_autorizacion(red, asumir_si=args.si):
        print("Operacion cancelada.")
        return 0, [], "", "", ""
    return None, [red], args.intensidad, "", ""


def _cmd_scan(args: argparse.Namespace) -> int:
    """Descubre equipos, inventaria puertos y muestra el riesgo por pantalla."""
    codigo, redes, intensidad, _, _ = _resolver_objetivo(args)
    if codigo is not None:
        return codigo

    print(f"\nAuditando (intensidad: {intensidad})...")
    try:
        equipos = auditar_redes(redes, intensidad=intensidad)
    except DescubrimientoError as exc:
        print(f"No se pudo completar la auditoria: {exc}", file=sys.stderr)
        return 1

    if not equipos:
        print("No se encontraron equipos activos.")
        return 0

    for equipo in equipos:
        nombre = equipo.hostname or "(sin nombre)"
        print(f"\n  {equipo.ip:<16} {nombre}  [riesgo: {equipo.nivel}]  (red {equipo.red})")
        if not equipo.hallazgos:
            print("      (sin puertos comunes abiertos)")
            continue
        for h in equipo.hallazgos:
            cred = "  (revisar credenciales de fabrica)" if h.revisar_credenciales else ""
            print(f"      [{h.nivel}] puerto {h.puerto} {h.servicio}{cred}")
            print(f"            {h.motivo}")
            print(f"            Recomendacion: {h.recomendacion}")

    print(f"\nEquipos inventariados: {len(equipos)}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Ejecuta la auditoria y guarda el informe en un archivo (md/html)."""
    codigo, redes, intensidad, institucion, responsable = _resolver_objetivo(args)
    if codigo is not None:
        return codigo
    if args.institucion:
        institucion = args.institucion

    print(f"\nAuditando (intensidad: {intensidad})...")
    try:
        equipos = auditar_redes(redes, intensidad=intensidad)
    except DescubrimientoError as exc:
        print(f"No se pudo completar la auditoria: {exc}", file=sys.stderr)
        return 1

    fecha = date.today().isoformat()
    if args.formato == "md":
        contenido = generar_markdown(equipos, institucion, responsable, fecha)
        extension = "md"
    else:
        contenido = generar_html(equipos, institucion, responsable, fecha)
        extension = "html"

    if args.salida:
        ruta = Path(args.salida)
    else:
        ruta = Path("informes") / f"informe-{fecha}.{extension}"
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(contenido, encoding="utf-8")

    print(f"Informe guardado en: {ruta}")
    print(f"Equipos incluidos: {len(equipos)}")
    if extension == "html":
        print("Sugerencia: abrelo en el navegador y usa 'Imprimir -> Guardar como PDF'.")
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


def _mostrar_equipos(equipos: list, sangria: str = "") -> None:
    if not equipos:
        print(f"{sangria}No se encontraron equipos activos.")
        return

    print(f"{sangria}Equipos activos encontrados: {len(equipos)}")
    for equipo in equipos:
        nombre = equipo.hostname or "(sin nombre)"
        print(f"{sangria}  {equipo.ip:<16} {nombre}")


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
    _agregar_args_objetivo(p_discover)
    p_discover.set_defaults(func=_cmd_discover)

    p_scan = subparsers.add_parser(
        "scan",
        help="Descubre equipos e inventaria sus puertos/servicios abiertos.",
    )
    _agregar_args_objetivo(p_scan)
    p_scan.set_defaults(func=_cmd_scan)

    p_report = subparsers.add_parser(
        "report",
        help="Ejecuta la auditoria y genera un informe (Markdown o HTML).",
    )
    _agregar_args_objetivo(p_report)
    p_report.add_argument(
        "--formato",
        default="html",
        choices=("html", "md"),
        help="Formato del informe (por defecto: html, imprimible a PDF).",
    )
    p_report.add_argument(
        "--salida",
        default=None,
        help="Ruta del archivo de salida (por defecto: informes/informe-FECHA.EXT).",
    )
    p_report.add_argument(
        "--institucion",
        default=None,
        help="Nombre de la institucion para el encabezado del informe.",
    )
    p_report.set_defaults(func=_cmd_report)

    return parser


def _agregar_args_objetivo(sub: argparse.ArgumentParser) -> None:
    """Argumentos comunes para elegir qué red(es) analizar."""
    sub.add_argument(
        "--config",
        default=None,
        help=(
            "Archivo de configuracion con varias subredes autorizadas (modo "
            "multi-sala). Tiene prioridad sobre --red y la auto-deteccion."
        ),
    )
    sub.add_argument(
        "--red",
        default=None,
        help="Red a escanear en notacion CIDR. Si se omite, se auto-detecta.",
    )
    sub.add_argument(
        "--prefijo",
        type=int,
        default=24,
        help="Tamano de prefijo al auto-detectar (por defecto: 24).",
    )
    sub.add_argument(
        "--intensidad",
        default="suave",
        choices=("suave", "normal"),
        help="Intensidad del escaneo (por defecto: suave).",
    )
    sub.add_argument(
        "--si",
        action="store_true",
        help="Asume 'si' en la confirmacion de autorizacion (uso no interactivo).",
    )


def main(argv: list[str] | None = None) -> int:
    parser = construir_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
