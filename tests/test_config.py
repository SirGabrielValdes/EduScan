"""Pruebas de la carga y validación de la configuración."""

from __future__ import annotations

import ipaddress

import pytest

from eduscan.config import ConfigError, validar_config


def _config_valida() -> dict:
    return {
        "autorizacion": {
            "institucion": "Colegio de prueba",
            "autoriza": "Dirección",
            "responsable": "Área de TI",
            "autorizado": True,
        },
        "subredes": ["192.168.1.0/24"],
        "intensidad": "suave",
        "chequeos": {"descubrimiento_equipos": True},
    }


def test_config_valida_se_carga():
    config = validar_config(_config_valida())
    assert config.autorizacion.institucion == "Colegio de prueba"
    assert config.subredes == [ipaddress.ip_network("192.168.1.0/24")]
    assert config.intensidad == "suave"
    # Los chequeos no mencionados quedan activados por defecto.
    assert config.chequeos["descubrimiento_equipos"] is True
    assert config.chequeos["inventario_servicios"] is True


def test_falla_si_no_esta_autorizado():
    datos = _config_valida()
    datos["autorizacion"]["autorizado"] = False
    with pytest.raises(ConfigError, match="no está autorizado"):
        validar_config(datos)


def test_falla_sin_subredes():
    datos = _config_valida()
    datos["subredes"] = []
    with pytest.raises(ConfigError, match="al menos una subred"):
        validar_config(datos)


def test_falla_con_subred_invalida():
    datos = _config_valida()
    datos["subredes"] = ["no-es-una-red"]
    with pytest.raises(ConfigError, match="Subred inválida"):
        validar_config(datos)


def test_falla_con_intensidad_invalida():
    datos = _config_valida()
    datos["intensidad"] = "agresiva"
    with pytest.raises(ConfigError, match="intensidad"):
        validar_config(datos)


def test_falla_con_chequeo_desconocido():
    datos = _config_valida()
    datos["chequeos"] = {"chequeo_inexistente": True}
    with pytest.raises(ConfigError, match="desconocidos"):
        validar_config(datos)


def test_faltan_campos_de_autorizacion():
    datos = _config_valida()
    datos["autorizacion"]["responsable"] = ""
    with pytest.raises(ConfigError, match="responsable"):
        validar_config(datos)
