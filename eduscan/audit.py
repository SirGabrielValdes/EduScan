"""Orquestación de la auditoría: descubrir, inventariar y analizar.

Parte del *motor*. Une las piezas (descubrimiento, escaneo de puertos y análisis
de riesgo) en un resultado estructurado. Al devolver datos (y no texto), sirve
por igual a la CLI, al generador de informes y a una futura interfaz web.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from eduscan.discovery import descubrir_equipos
from eduscan.risk import Hallazgo, analizar_servicios, nivel_maximo
from eduscan.scanning import escanear_puertos


@dataclass(frozen=True)
class EquipoAuditado:
    """Resultado de auditar un equipo: sus hallazgos y su nivel de riesgo."""

    red: str
    ip: str
    hostname: str | None
    hallazgos: list[Hallazgo] = field(default_factory=list)

    @property
    def nivel(self) -> str:
        return nivel_maximo(self.hallazgos)


def auditar_redes(
    redes: list[ipaddress.IPv4Network],
    intensidad: str = "suave",
) -> list[EquipoAuditado]:
    """Audita una o varias redes de punta a punta.

    Para cada red: descubre equipos vivos, inventaría sus puertos y analiza el
    riesgo de cada servicio.

    Returns:
        Lista de :class:`EquipoAuditado`, ordenada por gravedad (más grave
        primero) y luego por IP.
    """
    resultados: list[EquipoAuditado] = []
    for red in redes:
        for equipo in descubrir_equipos(red, intensidad=intensidad):
            servicios = escanear_puertos(equipo.ip, intensidad=intensidad)
            hallazgos = analizar_servicios(servicios)
            resultados.append(
                EquipoAuditado(
                    red=str(red),
                    ip=equipo.ip,
                    hostname=equipo.hostname,
                    hallazgos=hallazgos,
                )
            )
    return ordenar_por_riesgo(resultados)


def ordenar_por_riesgo(equipos: list[EquipoAuditado]) -> list[EquipoAuditado]:
    """Ordena los equipos de mayor a menor riesgo, y por IP como desempate."""
    from eduscan.risk import NIVELES

    return sorted(
        equipos,
        key=lambda e: (-NIVELES[e.nivel], ipaddress.ip_address(e.ip)),
    )


def resumen_por_nivel(equipos: list[EquipoAuditado]) -> dict[str, int]:
    """Cuenta cuántos equipos hay en cada nivel de riesgo."""
    conteo = {"ALTO": 0, "MEDIO": 0, "BAJO": 0, "INFO": 0}
    for equipo in equipos:
        conteo[equipo.nivel] += 1
    return conteo
