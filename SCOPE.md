# Alcance y autorización

Este documento define el **marco de autorización** bajo el cual se ejecuta
EduScan. Debe completarse y aprobarse **antes** de cualquier escaneo. EduScan
está diseñado para operar **solo** sobre las subredes listadas aquí y reflejadas
en el archivo de configuración (`config.yaml`).

## Autorización

- **Institución:** _(nombre del colegio)_
- **Autoriza (nombre y cargo):** _(p. ej. Director/a, Coordinador/a de TI)_
- **Responsable técnico que ejecuta:** _(tu nombre y cargo)_
- **Fecha de autorización:** _(AAAA-MM-DD)_
- **Ventana(s) autorizada(s) de ejecución:** _(p. ej. fuera de horario de clases)_

## Subredes dentro del alcance

Solo estas subredes pueden ser analizadas. Deben coincidir con las de
`config.yaml`.

| Subred (CIDR)   | Descripción                    |
|-----------------|--------------------------------|
| `192.168.1.0/24`| _(ejemplo: red administrativa)_ |

## Fuera de alcance (explícito)

- Cualquier red o equipo no listado arriba.
- Redes de terceros, redes de invitados de terceros, Internet.
- Dispositivos personales del personal o del alumnado, salvo autorización expresa.

## Principios de operación

- **No intrusivo:** EduScan detecta y reporta; no explota ni fuerza credenciales.
- **Intensidad suave por defecto:** para no afectar equipos frágiles (impresoras,
  cámaras, etc.).
- **Trazabilidad:** cada ejecución debería quedar registrada (fecha, operador,
  alcance) para rendición de cuentas ante la dirección.
