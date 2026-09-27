"""Pruebas de detección de red y del cálculo de hosts."""

from __future__ import annotations

import ipaddress

import pytest

from eduscan.discovery import Equipo, contar_hosts, descubrir_en_redes
from eduscan.network import RedError, detectar_red_local


def test_contar_hosts_de_un_24():
    red = ipaddress.ip_network("192.168.1.0/24")
    # Un /24 tiene 254 direcciones asignables (excluye red y broadcast).
    assert contar_hosts(red) == 254


def test_contar_hosts_de_un_30():
    red = ipaddress.ip_network("192.168.1.0/30")
    assert contar_hosts(red) == 2


def test_detectar_red_local_devuelve_una_red(monkeypatch):
    monkeypatch.setattr(
        "eduscan.network.detectar_ip_local", lambda: "192.168.10.50"
    )
    red = detectar_red_local(prefijo=24)
    assert red == ipaddress.ip_network("192.168.10.0/24")


def test_detectar_red_local_rechaza_prefijo_invalido():
    with pytest.raises(RedError):
        detectar_red_local(prefijo=40)


def test_descubrir_en_redes_agrupa_por_red(monkeypatch):
    # Simulamos que solo dos IPs concretas responden, sin tocar la red real.
    vivos = {"192.168.1.5", "192.168.2.3"}
    monkeypatch.setattr(
        "eduscan.discovery._esta_vivo", lambda ip: ip in vivos
    )
    monkeypatch.setattr(
        "eduscan.discovery._resolver_hostname", lambda ip: None
    )

    redes = [
        ipaddress.ip_network("192.168.1.0/29"),
        ipaddress.ip_network("192.168.2.0/29"),
    ]
    resultados = descubrir_en_redes(redes, intensidad="suave")

    assert set(resultados.keys()) == {"192.168.1.0/29", "192.168.2.0/29"}
    assert resultados["192.168.1.0/29"] == [Equipo(ip="192.168.1.5")]
    assert resultados["192.168.2.0/29"] == [Equipo(ip="192.168.2.3")]
