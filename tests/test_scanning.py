"""Pruebas del inventario de puertos/servicios.

Levantamos un servidor TCP local en un puerto libre para comprobar detección de
puertos abiertos, sin depender de la red externa.
"""

from __future__ import annotations

import socket

from eduscan.scanning import Servicio, escanear_puertos


def _abrir_puerto_local() -> tuple[socket.socket, int]:
    """Abre un socket que escucha en un puerto libre y lo devuelve."""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.bind(("127.0.0.1", 0))  # 0 = el SO elige un puerto libre
    servidor.listen()
    puerto = servidor.getsockname()[1]
    return servidor, puerto


def test_detecta_un_puerto_abierto():
    servidor, puerto = _abrir_puerto_local()
    try:
        puertos = {puerto: "Servicio de prueba"}
        servicios = escanear_puertos("127.0.0.1", puertos=puertos)
        assert servicios == [Servicio(puerto=puerto, nombre="Servicio de prueba")]
    finally:
        servidor.close()


def test_puerto_cerrado_no_aparece():
    servidor, puerto = _abrir_puerto_local()
    servidor.close()  # ahora el puerto está cerrado
    servicios = escanear_puertos("127.0.0.1", puertos={puerto: "Cerrado"})
    assert servicios == []


def test_ordena_por_numero_de_puerto():
    s1, p1 = _abrir_puerto_local()
    s2, p2 = _abrir_puerto_local()
    try:
        puertos = {p1: "A", p2: "B"}
        servicios = escanear_puertos("127.0.0.1", puertos=puertos)
        numeros = [s.puerto for s in servicios]
        assert numeros == sorted(numeros)
        assert len(servicios) == 2
    finally:
        s1.close()
        s2.close()
