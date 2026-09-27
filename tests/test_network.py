"""Pruebas de detección de red y del cálculo de hosts."""

from __future__ import annotations

import ipaddress

import pytest

from eduscan.discovery import contar_hosts
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
