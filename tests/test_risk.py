"""Pruebas del análisis de riesgo."""

from __future__ import annotations

from eduscan.risk import analizar_servicios, nivel_maximo
from eduscan.scanning import Servicio


def test_telnet_es_riesgo_alto_y_revisa_credenciales():
    hallazgos = analizar_servicios([Servicio(puerto=23, nombre="Telnet")])
    assert len(hallazgos) == 1
    assert hallazgos[0].nivel == "ALTO"
    assert hallazgos[0].revisar_credenciales is True


def test_https_es_informativo():
    hallazgos = analizar_servicios([Servicio(puerto=443, nombre="HTTPS")])
    assert hallazgos[0].nivel == "INFO"
    assert hallazgos[0].revisar_credenciales is False


def test_puerto_desconocido_es_informativo():
    hallazgos = analizar_servicios([Servicio(puerto=12345, nombre="Desconocido")])
    assert hallazgos[0].nivel == "INFO"


def test_hallazgos_ordenados_por_gravedad():
    servicios = [
        Servicio(puerto=443, nombre="HTTPS"),   # INFO
        Servicio(puerto=445, nombre="SMB"),     # MEDIO
        Servicio(puerto=3389, nombre="RDP"),    # ALTO
    ]
    niveles = [h.nivel for h in analizar_servicios(servicios)]
    assert niveles == ["ALTO", "MEDIO", "INFO"]


def test_nivel_maximo():
    servicios = [Servicio(puerto=443, nombre="HTTPS"), Servicio(puerto=23, nombre="Telnet")]
    assert nivel_maximo(analizar_servicios(servicios)) == "ALTO"


def test_nivel_maximo_sin_hallazgos():
    assert nivel_maximo([]) == "INFO"


def test_camara_rtsp_es_riesgo_alto_con_credenciales():
    hallazgos = analizar_servicios([Servicio(puerto=554, nombre="RTSP")])
    assert hallazgos[0].nivel == "ALTO"
    assert hallazgos[0].revisar_credenciales is True


def test_bases_de_datos_expuestas_son_riesgo_alto():
    for puerto in (6379, 27017):
        hallazgos = analizar_servicios([Servicio(puerto=puerto, nombre="BD")])
        assert hallazgos[0].nivel == "ALTO"


def test_todos_los_puertos_comunes_tienen_analisis():
    # Cada puerto conocido debe producir un hallazgo con un nivel valido.
    from eduscan.risk import NIVELES
    from eduscan.scanning import PUERTOS_COMUNES

    servicios = [Servicio(puerto=p, nombre=n) for p, n in PUERTOS_COMUNES.items()]
    hallazgos = analizar_servicios(servicios)
    assert len(hallazgos) == len(PUERTOS_COMUNES)
    assert all(h.nivel in NIVELES for h in hallazgos)
