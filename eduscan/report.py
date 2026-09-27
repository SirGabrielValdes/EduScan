"""Generación del informe para directivos (Markdown y HTML).

Parte del *motor*. Convierte los resultados de la auditoría en un documento
claro y priorizado. El HTML está pensado para leerse en el navegador y guardarse
como PDF con "Imprimir → Guardar como PDF", sin librerías extra.
"""

from __future__ import annotations

import html
from datetime import date

from eduscan.audit import EquipoAuditado, resumen_por_nivel

# Texto y color asociados a cada nivel de riesgo (semáforo).
_ETIQUETA = {
    "ALTO": "Riesgo alto",
    "MEDIO": "Riesgo medio",
    "BAJO": "Riesgo bajo",
    "INFO": "Informativo",
}
_COLOR = {
    "ALTO": "#c0392b",
    "MEDIO": "#e67e22",
    "BAJO": "#f1c40f",
    "INFO": "#7f8c8d",
}


def _fecha_hoy() -> str:
    return date.today().isoformat()


def generar_markdown(
    equipos: list[EquipoAuditado],
    institucion: str = "",
    responsable: str = "",
    fecha: str | None = None,
) -> str:
    """Genera el informe en formato Markdown."""
    fecha = fecha or _fecha_hoy()
    conteo = resumen_por_nivel(equipos)
    lineas: list[str] = []

    lineas.append("# Informe de seguridad de red - EduScan")
    lineas.append("")
    if institucion:
        lineas.append(f"**Institución:** {institucion}  ")
    if responsable:
        lineas.append(f"**Responsable:** {responsable}  ")
    lineas.append(f"**Fecha:** {fecha}")
    lineas.append("")

    lineas.append("## Resumen ejecutivo")
    lineas.append("")
    lineas.append(f"- Equipos analizados: **{len(equipos)}**")
    lineas.append(f"- Riesgo alto: **{conteo['ALTO']}**")
    lineas.append(f"- Riesgo medio: **{conteo['MEDIO']}**")
    lineas.append(f"- Riesgo bajo: **{conteo['BAJO']}**")
    lineas.append(f"- Informativos: **{conteo['INFO']}**")
    lineas.append("")

    prioritarios = [e for e in equipos if e.nivel in ("ALTO", "MEDIO")]
    lineas.append("## Prioridades de mejora")
    lineas.append("")
    if not prioritarios:
        lineas.append("No se detectaron equipos de riesgo alto o medio.")
    else:
        for i, equipo in enumerate(prioritarios, start=1):
            nombre = equipo.hostname or "(sin nombre)"
            lineas.append(
                f"{i}. **{equipo.ip}** ({nombre}) - {_ETIQUETA[equipo.nivel]}"
            )
            for h in equipo.hallazgos:
                if h.nivel in ("ALTO", "MEDIO"):
                    lineas.append(f"   - [{h.nivel}] {h.servicio}: {h.recomendacion}")
    lineas.append("")

    lineas.append("## Detalle por equipo")
    lineas.append("")
    for equipo in equipos:
        nombre = equipo.hostname or "(sin nombre)"
        lineas.append(f"### {equipo.ip} - {nombre} [{_ETIQUETA[equipo.nivel]}]")
        lineas.append(f"Red: {equipo.red}")
        lineas.append("")
        if not equipo.hallazgos:
            lineas.append("Sin puertos comunes abiertos.")
        else:
            for h in equipo.hallazgos:
                cred = " (revisar credenciales de fábrica)" if h.revisar_credenciales else ""
                lineas.append(f"- **[{h.nivel}] Puerto {h.puerto} - {h.servicio}**{cred}")
                lineas.append(f"  - {h.motivo}")
                lineas.append(f"  - Recomendación: {h.recomendacion}")
        lineas.append("")

    lineas.append("---")
    lineas.append(
        "_Informe generado por EduScan en un entorno autorizado. "
        "EduScan detecta y reporta; no explota vulnerabilidades ni prueba contraseñas._"
    )
    return "\n".join(lineas)


def generar_html(
    equipos: list[EquipoAuditado],
    institucion: str = "",
    responsable: str = "",
    fecha: str | None = None,
) -> str:
    """Genera el informe en HTML (imprimible a PDF desde el navegador)."""
    fecha = fecha or _fecha_hoy()
    conteo = resumen_por_nivel(equipos)
    e = html.escape

    def badge(nivel: str) -> str:
        return (
            f'<span style="background:{_COLOR[nivel]};color:#fff;padding:2px 8px;'
            f'border-radius:4px;font-size:0.85em;">{e(_ETIQUETA[nivel])}</span>'
        )

    partes: list[str] = []
    partes.append("<!DOCTYPE html>")
    partes.append('<html lang="es"><head><meta charset="utf-8">')
    partes.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    partes.append("<title>Informe de seguridad de red - EduScan</title>")
    partes.append(
        "<style>"
        "body{font-family:Arial,Helvetica,sans-serif;color:#222;max-width:900px;"
        "margin:2rem auto;padding:0 1rem;line-height:1.5;}"
        "h1{border-bottom:3px solid #2c3e50;padding-bottom:.3rem;}"
        "h2{margin-top:2rem;color:#2c3e50;}"
        "table{border-collapse:collapse;width:100%;margin:1rem 0;}"
        "th,td{border:1px solid #ddd;padding:.5rem;text-align:left;}"
        "th{background:#f4f6f7;}"
        ".resumen{display:flex;gap:1rem;flex-wrap:wrap;}"
        ".tarjeta{border:1px solid #ddd;border-radius:6px;padding:1rem;min-width:120px;text-align:center;}"
        ".tarjeta .num{font-size:1.8rem;font-weight:bold;}"
        ".equipo{border:1px solid #eee;border-radius:6px;padding:1rem;margin:1rem 0;}"
        ".pie{margin-top:2rem;color:#777;font-size:.9em;border-top:1px solid #eee;padding-top:1rem;}"
        "@media print{body{margin:0;}}"
        "</style></head><body>"
    )

    partes.append("<h1>Informe de seguridad de red</h1>")
    datos = []
    if institucion:
        datos.append(f"<strong>Institución:</strong> {e(institucion)}")
    if responsable:
        datos.append(f"<strong>Responsable:</strong> {e(responsable)}")
    datos.append(f"<strong>Fecha:</strong> {e(fecha)}")
    partes.append("<p>" + "<br>".join(datos) + "</p>")

    partes.append("<h2>Resumen ejecutivo</h2>")
    partes.append('<div class="resumen">')
    tarjetas = [
        ("Analizados", len(equipos), "#2c3e50"),
        ("Riesgo alto", conteo["ALTO"], _COLOR["ALTO"]),
        ("Riesgo medio", conteo["MEDIO"], _COLOR["MEDIO"]),
        ("Riesgo bajo", conteo["BAJO"], _COLOR["BAJO"]),
        ("Informativos", conteo["INFO"], _COLOR["INFO"]),
    ]
    for titulo, num, color in tarjetas:
        partes.append(
            f'<div class="tarjeta"><div class="num" style="color:{color}">{num}</div>'
            f"<div>{e(titulo)}</div></div>"
        )
    partes.append("</div>")

    prioritarios = [eq for eq in equipos if eq.nivel in ("ALTO", "MEDIO")]
    partes.append("<h2>Prioridades de mejora</h2>")
    if not prioritarios:
        partes.append("<p>No se detectaron equipos de riesgo alto o medio.</p>")
    else:
        partes.append("<table><tr><th>#</th><th>Equipo</th><th>Riesgo</th>"
                      "<th>Acciones principales</th></tr>")
        for i, equipo in enumerate(prioritarios, start=1):
            nombre = equipo.hostname or "(sin nombre)"
            acciones = "<br>".join(
                f"{e(h.servicio)}: {e(h.recomendacion)}"
                for h in equipo.hallazgos
                if h.nivel in ("ALTO", "MEDIO")
            )
            partes.append(
                f"<tr><td>{i}</td><td>{e(equipo.ip)}<br><small>{e(nombre)}</small></td>"
                f"<td>{badge(equipo.nivel)}</td><td>{acciones}</td></tr>"
            )
        partes.append("</table>")

    partes.append("<h2>Detalle por equipo</h2>")
    for equipo in equipos:
        nombre = equipo.hostname or "(sin nombre)"
        partes.append('<div class="equipo">')
        partes.append(
            f"<h3>{e(equipo.ip)} - {e(nombre)} {badge(equipo.nivel)}</h3>"
            f"<p><small>Red: {e(equipo.red)}</small></p>"
        )
        if not equipo.hallazgos:
            partes.append("<p>Sin puertos comunes abiertos.</p>")
        else:
            partes.append("<ul>")
            for h in equipo.hallazgos:
                cred = " (revisar credenciales de fábrica)" if h.revisar_credenciales else ""
                partes.append(
                    f"<li><strong>[{e(h.nivel)}] Puerto {h.puerto} - {e(h.servicio)}</strong>"
                    f"{e(cred)}<br>{e(h.motivo)}<br>"
                    f"<em>Recomendación:</em> {e(h.recomendacion)}</li>"
                )
            partes.append("</ul>")
        partes.append("</div>")

    partes.append(
        '<div class="pie">Informe generado por EduScan en un entorno autorizado. '
        "EduScan detecta y reporta; no explota vulnerabilidades ni prueba contraseñas.</div>"
    )
    partes.append("</body></html>")
    return "\n".join(partes)
