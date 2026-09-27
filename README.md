# EduScan

Herramienta que analiza la red de un colegio **en un entorno autorizado** y
genera un informe claro para directivos: equipos expuestos, posibles contraseñas
por defecto y prioridades de mejora.

> ⚠️ **Uso autorizado únicamente.** EduScan está pensado para que el propio
> personal técnico de un colegio evalúe **su propia red**, con permiso explícito
> de la dirección. No debe usarse sobre redes de terceros ni fuera del alcance
> definido en [`SCOPE.md`](SCOPE.md). Escanear redes sin autorización es ilegal
> en la mayoría de países.

## ¿Qué hace EduScan?

- **Descubre** qué equipos están activos en las subredes autorizadas.
- **Identifica** qué servicios/puertos están expuestos en cada equipo.
- **Señala** configuraciones de riesgo comunes (protocolos inseguros, paneles de
  administración abiertos, etc.).
- **Advierte** sobre equipos que *probablemente* usan credenciales de fábrica,
  cruzando fabricante/modelo con una base de credenciales por defecto conocidas
  (no prueba contraseñas activamente).
- **Genera un informe** para directivos: resumen ejecutivo, equipos expuestos y
  prioridades de mejora.

## ¿Qué NO hace?

- No explota vulnerabilidades ni intenta "entrar" a los equipos.
- No hace fuerza bruta de contraseñas.
- No realiza ataques de denegación de servicio.
- No opera fuera de las subredes autorizadas en la configuración.

## Estado del proyecto

En construcción, paso a paso. Este primer ladrillo establece la **estructura**
y la **carga/validación de la configuración**. Todavía no escanea la red.

Hoja de ruta corta:

1. [x] Esqueleto del proyecto + configuración autorizada.
2. [x] Descubrimiento de equipos activos (con auto-detección de red).
3. [x] Escaneo multi-sala: recorrer varias subredes desde la configuración.
4. [ ] Inventario de servicios/puertos.
5. [ ] Chequeo de configuraciones de riesgo y credenciales por defecto (Opción A).
6. [ ] Generación del informe.
7. [ ] (Futuro) Interfaz web para que la dirección la ejecute sin depender del área técnica.

## Instalación (desarrollo)

```bash
python -m venv .venv
source .venv/bin/activate        # en Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Uso

```bash
# 1. Copia la plantilla y ajústala a tu colegio
cp config.example.yaml config.yaml

# 2. Edita config.yaml con tus subredes autorizadas y el marco de autorización

# 3. Valida que la configuración es correcta
python -m eduscan.cli validate --config config.yaml
```

### Descubrir equipos activos

```bash
# Auto-detecta la red donde está la laptop y pide confirmación (ideal en la sala)
python -m eduscan.cli discover

# Recorre TODAS las subredes autorizadas del config (modo multi-sala / central)
python -m eduscan.cli discover --config config.yaml

# Escanear una red concreta
python -m eduscan.cli discover --red 192.168.1.0/24
```

## Arquitectura

EduScan separa el **motor** (funciones puras en `eduscan/`) de la **interfaz**
(hoy la línea de comandos en `eduscan/cli.py`). Esto permite que en el futuro
una app web reutilice el mismo motor sin reescribirlo.
