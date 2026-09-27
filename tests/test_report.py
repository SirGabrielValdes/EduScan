"""Pruebas del generador de informes y del resumen de auditoría."""

from __future__ import annotations

from eduscan.audit import EquipoAuditado, ordenar_por_riesgo, resumen_por_nivel
from eduscan.report import generar_html, generar_markdown
from eduscan.risk import Hallazgo


def _equipo(ip: str, nivel: str) -> EquipoAuditado:
    hallazgo = Hallazgo(
        puerto=3389,
        servicio="RDP",
        nivel=nivel,
        motivo="Motivo de prueba",
        recomendacion="Recomendacion de prueba",
    )
    return EquipoAuditado(red="192.168.1.0/24", ip=ip, hostname="pc", hallazgos=[hallazgo])


def test_resumen_por_nivel_cuenta_bien():
    equipos = [_equipo("192.168.1.2", "ALTO"), _equipo("192.168.1.3", "MEDIO")]
    conteo = resumen_por_nivel(equipos)
    assert conteo["ALTO"] == 1
    assert conteo["MEDIO"] == 1
    assert conteo["BAJO"] == 0


def test_ordenar_por_riesgo_pone_alto_primero():
    equipos = [_equipo("192.168.1.5", "MEDIO"), _equipo("192.168.1.4", "ALTO")]
    ordenados = ordenar_por_riesgo(equipos)
    assert ordenados[0].nivel == "ALTO"


def test_markdown_incluye_encabezado_y_resumen():
    md = generar_markdown([_equipo("192.168.1.2", "ALTO")], institucion="Colegio X")
    assert "# Informe de seguridad de red" in md
    assert "Colegio X" in md
    assert "Prioridades de mejora" in md


def test_html_es_documento_valido():
    htmldoc = generar_html([_equipo("192.168.1.2", "ALTO")], institucion="Colegio X")
    assert htmldoc.startswith("<!DOCTYPE html>")
    assert "Colegio X" in htmldoc
    assert "Resumen ejecutivo" in htmldoc


def test_informe_sin_equipos_no_falla():
    md = generar_markdown([])
    assert "Equipos analizados: **0**" in md
