# Strix Runner

Consulta [CHANGELOG.md](CHANGELOG.md) para el histórico de cambios.

CLI en Python (solo biblioteca estándar) para guardar perfiles de aplicaciones y
ejecutar escaneos autorizados de Strix. La URL se pasa como primer `--target` y,
si se configura código local, este se pasa como un segundo `--target`, que es la
forma soportada por Strix para combinar análisis black-box y white-box.

Versión actual del runner: **1.12.0**. Puede consultarla desde la terminal con
cualquiera de estas formas:

```bash
python3 strix_runner.py version
python3 strix_runner.py --version
```

Para comprobar el JSON de configuración, sus perfiles y todas las rutas
referenciadas sin ejecutar Strix:

```bash
python3 strix_runner.py verify
```

Si el JSON se va a utilizar en otra máquina y solo desea comprobar su estructura:

```bash
python3 strix_runner.py verify --json-only
```

## Instalación

### Desde el repositorio APT (Ubuntu/Debian)

Añade el repositorio e instala el paquete:

```bash
echo "deb [trusted=yes] https://mikehenrytech.github.io/strix-runner stable main" | sudo tee /etc/apt/sources.list.d/strix-runner.list
sudo apt-get update
sudo apt-get install strix-runner
```

### Desde el binario standalone

Descarga el ejecutable desde la página de [releases](https://github.com/Mikehenrytech/strix-runner/releases):

```bash
wget https://github.com/Mikehenrytech/strix-runner/releases/latest/download/strix-runner-linux-x64
chmod +x strix-runner-linux-x64
sudo mv strix-runner-linux-x64 /usr/local/bin/strix-runner
```

### Desde el código fuente

```bash
python3 strix_runner.py --version
```

## Inicio rápido

```bash
python3 strix_runner.py configure \
  --path-base "$PATH_BASE" \
  --path-strix /ruta/desde/la/que/funciona/uv-run-strix

python3 strix_runner.py save mi-app-pre \
  -u 'https://app-autorizada.example.test' \
  -c repos/mi-app

python3 strix_runner.py list
python3 strix_runner.py run mi-app-pre --dry-run
python3 strix_runner.py run mi-app-pre
python3 strix_runner.py resume list
```

Las opciones `--url` y `--code-path` son repetibles. Cada valor se pasa a Strix
como un `--target` independiente:

```bash
python3 strix_runner.py save aplicacion-multitarget \
  -u https://frontend.example.test \
  -u https://api.example.test \
  -c github/frontend/code \
  -c github/backend/code
```

Para un análisis exclusivamente de caja blanca, guarde solo una o varias rutas
de código:

```bash
python3 strix_runner.py save mi-app-whitebox -c repos/mi-app
```

Un perfil debe tener al menos una URL o una ruta de código. Para quitar la URL
de un perfil existente:

```bash
python3 strix_runner.py save mi-app-pre --clear-url
```

## Levantar una aplicación local

Puede guardar un comando de arranque. Se ejecuta desde `code_path`, se espera el
tiempo configurado y después se inicia Strix:

```bash
python3 strix_runner.py save mi-app-local \
  -u http://localhost:8080 \
  -c repos/mi-app \
  --start-command "uv run python -m mi-app" \
  --start-wait-seconds 8
```

Si el proceso sigue vivo al terminar el análisis, el runner lo finaliza junto
con sus procesos hijos. Para servicios que se desacoplan (por ejemplo,
`docker compose up -d`), puede guardar también la parada:

```bash
python3 strix_runner.py save mi-app-local \
  --start-command "docker compose up -d" \
  --stop-command "docker compose down"
```

Los comandos en primer plano como `mvn spring-boot:run`, `npm start`,
`uv run app-start` y `make run` se ejecutan sin entrada de terminal dentro de
un grupo de procesos independiente. Al finalizar, el runner envía `SIGTERM` al
grupo completo y, si todavía quedan procesos tras el periodo de gracia, utiliza
`SIGKILL`. No necesitan `stop_command` salvo que se desacoplen o gestionen el
servicio fuera de ese grupo.

```bash
python3 strix_runner.py save aplicacion-local --stop-grace-seconds 15
```

El valor predeterminado es 10 segundos. PID, PGID y las señales de parada se
registran en `application.log`.

Cuando el perfil contiene varios repositorios y utiliza comandos de arranque o
parada, indique expresamente desde qué directorio se ejecutan:

```bash
python3 strix_runner.py save aplicacion-local \
  -c github/frontend/code \
  -c github/backend/code \
  --command-cwd github/backend/code \
  --start-command "docker compose up" \
  --stop-command "docker compose down"
```

Los comandos se separan en argumentos y no usan `shell=True`. Si necesita
operadores de shell, indíquelo de manera explícita, por ejemplo
`--start-command "sh -lc 'comando1 | comando2'"`. Use `run --skip-start` cuando
el servicio ya esté levantado. `--dry-run` muestra el arranque y Strix sin
ejecutar ninguno.

### Logs de la aplicación

La salida estándar y de error de `start_command` y `stop_command` se guarda por
separado para que no se mezcle con la salida de Strix:

```text
~/.local/state/strix-runner/logs/<ejecución>/<perfil>/application.log
```

El runner muestra la ruta antes de iniciar la aplicación. Los directorios y el
archivo usan permisos restrictivos. `--dry-run` muestra la ruta prevista sin
crear archivos y `--skip-start` no genera un log de aplicación.

```bash
python3 strix_runner.py configure --log-dir /ruta/protegida/logs
python3 strix_runner.py run app1 --app-log-dir ./logs-temporales
python3 strix_runner.py configure --clear-log-dir
```

Las rutas globales relativas parten de `PATH_BASE`; las pasadas a `run`
parten del directorio actual.

Al crear una aplicación se guardan automáticamente estos valores si no se
indican otros:

- `Instrucciones/Web_Application_Security_Assessment.md`
- `token.json`, `testp_pass.txt` y `mail_otp.py`
- `scan_mode = deep`

Las rutas relativas de instrucciones, workspace y código se resuelven respecto
a `PATH_BASE`. `PATH_STRIX` es el directorio de trabajo (`cwd`) del proceso
`uv run strix`.

## Selección y código opcional

Sin nombres, `run` muestra un selector numérico interactivo:

```bash
python3 strix_runner.py run
```

`list` muestra el ID de selección de cada perfil. Puede ejecutar una lista por
nombre, por ID o separando los ID con comas:

```bash
python3 strix_runner.py run app1 app2
python3 strix_runner.py run 1 3
python3 strix_runner.py run 1,3
python3 strix_runner.py run --all --keep-going
```

Los ID corresponden al orden alfabético mostrado por `list`; pueden cambiar al
añadir, renombrar o eliminar perfiles. Consulte `list` antes de automatizarlos.

`--keep-going` continúa con los perfiles restantes tanto si Strix devuelve un
código de error como si falla la validación, el arranque o un ejecutable de ese
perfil. El comando devuelve finalmente un estado distinto de cero si hubo
cualquier fallo.

## Resumen de resultados

Después de cada perfil, el runner correlaciona la ejecución con el `run.json`
creado por Strix y muestra su estado, duración, hallazgos por severidad, resumen
ejecutivo y ruta del informe. Al terminar imprime una tabla conjunta de todos
los perfiles. Un estado `completed` con hallazgos se distingue de un fallo
técnico; en modo no interactivo, el código `2` de Strix no impide ejecutar los
perfiles restantes cuando los artefactos confirman que el análisis terminó.

```bash
python3 strix_runner.py run 1,3 --report-summary short
python3 strix_runner.py run 1,3 --report-summary full
python3 strix_runner.py run 1,3 --report-summary none
```

`short` es el valor predeterminado y limita el resumen mostrado; `full` muestra
el resumen ejecutivo completo y `none` lo oculta en la terminal. Los resultados
estructurados se guardan con permisos privados junto a los logs:

```text
<LOG_DIR>/<ejecución>/summary.json
<LOG_DIR>/<ejecución>/summary.md
```

## Historial de análisis

`history` recorre `PATH_STRIX/strix_runs`, asocia las ejecuciones con los perfiles
actuales y las ordena por fecha sin modificar los artefactos de Strix:

```bash
python3 strix_runner.py history mi-app-pre
python3 strix_runner.py history mi-app-pre --from 2026-09-01 --to 2026-10-08
python3 strix_runner.py history mi-app-pre --details
python3 strix_runner.py history --all --json
python3 strix_runner.py history --all --run 3 --details
python3 strix_runner.py history 3 --details
python3 strix_runner.py history --id 3 --details
```

Cada fila recibe un ID según el orden cronológico de la consulta. `--run`
acepta ese ID, además del `run_id` o nombre persistido. Un ID posicional o
`--id` consultan directamente el historial completo, sin exigir `--all`.
Cuando se utilizan `--from`, `--to` o un perfil, repita los mismos filtros al
consultar el ID.

La vista detallada muestra el comando, su procedencia, los agentes y las skills
cargadas por cada agente. La utilidad se muestra como `High`, `Medium`, `Low` o
`No observable`; el runner no infiere valoraciones a partir de conversaciones.
Una valoración solo se acepta desde `.state/skill_audit.json` o desde metadatos
estructurados equivalentes.

Puede generar un informe interactivo autocontenido, sin CDN ni servidor web:

```bash
python3 strix_runner.py history mi-app-pre --html historial.html
python3 strix_runner.py history --all --html historial-completo.html
```

El HTML contiene rutas, objetivos y metadatos de los análisis, por lo que se
crea con permisos privados. No incluye los mensajes completos de
`.state/agents.db`. Las ejecuciones nuevas guardan además un
`strix-runner.json` privado junto a `run.json`; este archivo conserva el perfil
y los comandos observados. En ejecuciones anteriores, el comando se marca como
`reconstructed` y los argumentos no observables se indican expresamente.

### Reanudar una sesión

`resume` utiliza la restauración nativa de Strix para recuperar el historial
completo de los agentes y volver a entrar en la interfaz interactiva. Primero
puede listar las ejecuciones que conservan `run.json`, `.state/agents.json` y
`.state/agents.db`:

```bash
python3 strix_runner.py resume list
```

Los ID son los mismos que muestra el historial completo, aunque pueden existir
huecos cuando una ejecución no tiene estado reanudable. Puede seleccionar una
sesión por ID, `run_id` o nombre de directorio:

```bash
python3 strix_runner.py resume 3
python3 strix_runner.py resume nombre-del-run
python3 strix_runner.py resume 3 --dry-run
python3 strix_runner.py resume 3 --non-interactive
```

El runner ejecuta `uv run strix --resume <run_name>` desde `PATH_STRIX`, sin
reconstruir ni volver a pasar los objetivos. Strix restaura la conversación y
la topología de agentes, pero recrea sus servicios auxiliares; cualquier
aplicación objetivo necesaria debe seguir estando disponible.

### Dashboard web de solo lectura

El dashboard es una aplicación separada con backend Python y frontend React.
Presenta el historial completo, filtros, tendencias, comparación de runs,
agentes, skills y acceso controlado a los informes. No ejecuta Strix ni modifica
la configuración o sus artefactos.

Está publicado en el repositorio `strix-runner-dashboard`. Si los dos proyectos
están en carpetas hermanas, el dashboard localiza automáticamente a
`strix_runner.py`. También puedes indicar la ruta con la variable de entorno
`STRIX_RUNNER_PATH`.

Si Strix termina sin `scan_results`, el runner lo marca como `INCOMPLETA` y
muestra la ruta de los artefactos parciales, aunque el proceso haya devuelto
código cero.

Por defecto se pasan todas las URL y todos los repositorios guardados en el
perfil. Puede limitar el tipo de prueba por ejecución:

```bash
python3 strix_runner.py run app1 --only-code
python3 strix_runner.py run app1 --only-pentesting
```

`--only-code` exige al menos un repositorio y no ejecuta los comandos de
arranque/parada. `--only-pentesting` exige al menos una URL y sí conserva el
ciclo de la aplicación local cuando está configurado.

`--code-mode` se mantiene por compatibilidad:

```bash
python3 strix_runner.py run app1 --code-mode exclude
python3 strix_runner.py run app1 --code-mode include
```

`include` falla si algún perfil elegido no tiene código; `exclude` fuerza un
escaneo sin código y equivale a `--only-pentesting`.

## Instrucciones adicionales por ejecución

Puede guardar en cada perfil un archivo opcional de instrucciones adicionales.
Las rutas relativas se resuelven respecto a `PATH_BASE`:

```bash
python3 strix_runner.py save app1 \
  --additional-instruction-file Instrucciones/skill-audit.md
```

A partir de entonces se cargará automáticamente con cada `run`. Para eliminarlo:

```bash
python3 strix_runner.py save app1 --clear-additional-instruction-file
```

También puede sobrescribirlo puntualmente sin modificar el perfil:

```bash
python3 strix_runner.py run app1 \
  --additional-instruction-file ./additional-instruction.example.md
```

Cuando se pasa directamente a `run`, el archivo se interpreta respecto al
directorio actual. Su contenido se combina con las instrucciones configuradas
en un archivo temporal con permisos restrictivos. Strix recibe un único
`--instruction-file`, ya que su CLI no permite combinarlo con `--instruction`.
El archivo temporal se elimina incluso si la ejecución falla. `--dry-run`
comprueba y combina los archivos, muestra el comando y elimina inmediatamente
el temporal sin ejecutar Strix.

No incluya secretos en archivos versionados. Para solicitar información de
diagnóstico, pida expresamente que no se infieran datos que los agentes no
puedan observar.

## Configuración

Por defecto se guarda con permisos de usuario en
`~/.config/strix-runner/config.json`. Puede elegir otro archivo antes del
subcomando o mediante `STRIX_RUNNER_CONFIG`:

```bash
python3 strix_runner.py --config ./strix.json configure \
  --path-base /datos/base --path-strix /opt/strix
python3 strix_runner.py --config ./strix.json run mi-app-pre --dry-run
```

Para sustituir los archivos de workspace, repita `-w`. Para actualizar un
perfil se vuelve a usar `save`; solo cambian los campos suministrados:

```bash
python3 strix_runner.py save mi-app-pre \
  -w token.json -w testp_pass.txt -w mail_otp.py
python3 strix_runner.py save mi-app-pre --clear-code
```

Antes de ejecutar se comprueban `PATH_STRIX`, las instrucciones y los archivos
de workspace. `--no-validate` permite únicamente omitir esas comprobaciones.
Los procesos se lanzan con una lista de argumentos y sin `shell=True`.

Use la herramienta solo contra sistemas para los que tenga autorización.

## Licencia

Este proyecto está licenciado bajo
[Creative Commons Attribution-NonCommercial 4.0 International](LICENSE).

- **Uso personal e individual**: libre, con atribución al autor y sin fines
  comerciales.
- **Uso por organizaciones**: cualquier uso por parte de empresas,
  instituciones, asociaciones, fundaciones, entidades públicas o privadas, o
  cualquier otra persona jurídica —incluido el uso interno, académico o sin
  fines de lucro directo— requiere **autorización previa y expresa del
  autor**.

Consulta el [adendum de licencia](LICENSE-ADDENDUM.md) para más detalles.
