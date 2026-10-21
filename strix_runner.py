#!/usr/bin/env python3
"""Profile-based launcher for Strix pentests.

The program only uses Python's standard library.  It stores two global paths
and any number of application profiles in a JSON file, then builds/runs Strix
commands without invoking a shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import shlex
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Sequence
from urllib.parse import urlparse


DEFAULT_INSTRUCTION_FILE = "Instrucciones/Web_Application_Security_Assessment.md"
DEFAULT_WORKSPACE_FILES = ["token.json", "testp_pass.txt", "mail_otp.py"]
DEFAULT_SCAN_MODE = "deep"
__version__ = "1.11.0"
DEFAULT_LOG_DIR = (
    Path(os.environ.get("XDG_STATE_HOME", "~/.local/state")).expanduser()
    / "strix-runner"
    / "logs"
)
DEFAULT_CONFIG = Path(
    os.environ.get(
        "STRIX_RUNNER_CONFIG", "~/.config/strix-runner/config.json"
    )
).expanduser()


class UserError(Exception):
    """An error that should be shown without a traceback."""


@dataclass(frozen=True)
class StrixRunSnapshot:
    """Observable state of a Strix run record before launching a profile."""

    modified_ns: int
    size: int


@dataclass
class ExecutionResult:
    """Normalized outcome of one application profile execution."""

    profile: str
    returncode: int
    outcome: str
    strix_status: str | None = None
    run_name: str | None = None
    run_dir: str | None = None
    report_path: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    duration_seconds: float | None = None
    findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    executive_summary: str | None = None
    error: str | None = None

    @property
    def is_operational_failure(self) -> bool:
        """Whether this result should trigger fail-fast behavior."""
        if self.outcome == "ERROR":
            return True
        if self.strix_status == "completed" and self.returncode == 2:
            return False
        return self.returncode != 0


class ApplicationInterrupted(Exception):
    """Carry partial Strix artifacts out of a user-interrupted profile."""

    def __init__(self, result: ExecutionResult):
        self.result = result
        super().__init__(f"Ejecución interrumpida: {result.profile}")


@dataclass(frozen=True)
class ManagedProcess:
    """A local application process and its isolated process-group identity."""

    process: subprocess.Popen[Any]
    group_id: int | None


@dataclass
class HistorySkill:
    """One skill loaded by an agent during a historical Strix run."""

    name: str
    utility: str = "not_observable"
    reason: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class HistoryAgent:
    """Normalized agent information persisted by Strix."""

    agent_id: str
    name: str
    status: str | None = None
    task: str | None = None
    skills: list[HistorySkill] = field(default_factory=list)


@dataclass
class HistoryRun:
    """Normalized, serializable view of one historical Strix execution."""

    selection_id: int
    run_id: str | None
    run_name: str
    run_dir: str
    profile: str | None
    profile_source: str
    profile_candidates: list[str]
    start_time: str | None
    end_time: str | None
    date_source: str
    status: str
    scan_mode: str | None
    duration_seconds: float | None
    targets: list[str]
    findings: int | None
    severity_counts: dict[str, int]
    findings_source: str
    report_path: str | None
    report_uri: str | None
    command: list[str]
    command_display: str
    command_source: str
    command_gaps: list[str]
    agents: list[HistoryAgent]
    llm_usage: dict[str, int | float]


STRIX_RUN_RECORD = "run.json"
STRIX_RUNS_DIRECTORY = "strix_runs"
RUNNER_RUN_RECORD = "strix-runner.json"
SKILL_AUDIT_RECORD = "skill_audit.json"
MAX_RUN_RECORD_BYTES = 5 * 1024 * 1024
MAX_VULNERABILITIES_BYTES = 25 * 1024 * 1024
MAX_AGENTS_STATE_BYTES = 25 * 1024 * 1024
MAX_RUNNER_RECORD_BYTES = 2 * 1024 * 1024
SUMMARY_PREVIEW_CHARS = 1_200
ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
UTILITY_RATINGS = {"high", "medium", "low", "not_observable"}


def empty_config() -> dict[str, Any]:
    return {"version": 1, "globals": {}, "applications": {}}


def load_config(path: Path, *, must_exist: bool = True) -> dict[str, Any]:
    if not path.exists():
        if must_exist:
            raise UserError(
                f"No existe la configuración {path}. Ejecuta primero 'configure'."
            )
        return empty_config()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UserError(f"No se pudo leer {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise UserError(f"La raíz de {path} debe ser un objeto JSON.")
    if data.get("version") != 1:
        raise UserError("Versión de configuración no soportada (se esperaba version=1).")
    if not isinstance(data.get("globals"), dict) or not isinstance(
        data.get("applications"), dict
    ):
        raise UserError("La configuración debe contener 'globals' y 'applications'.")
    validate_config(data)
    return data


def save_config(path: Path, config: dict[str, Any]) -> None:
    """Atomically save config with owner-only permissions when possible."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def resolve_from(base: Path, value: str) -> Path:
    expanded = Path(os.path.expandvars(value)).expanduser()
    return expanded if expanded.is_absolute() else base / expanded


def validate_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise UserError(f"URL no válida: {value!r}")


def profile_values(
    name: str,
    profile: dict[str, Any],
    singular: str,
    plural: str,
) -> list[str]:
    """Return a normalized list while supporting the legacy singular field."""
    if singular in profile and plural in profile:
        raise UserError(
            f"El perfil {name!r} no puede contener simultáneamente "
            f"{singular!r} y {plural!r}."
        )
    if plural in profile:
        values = profile[plural]
        if not isinstance(values, list) or not all(
            isinstance(value, str) and value.strip() for value in values
        ):
            raise UserError(f"{plural} de {name!r} debe ser una lista de textos no vacíos.")
        return values
    value = profile.get(singular)
    if value is None:
        return []
    if not isinstance(value, str) or not value.strip():
        raise UserError(f"{singular} de {name!r} debe ser un texto no vacío.")
    return [value]


def profile_urls(name: str, profile: dict[str, Any]) -> list[str]:
    return profile_values(name, profile, "url", "urls")


def profile_code_paths(name: str, profile: dict[str, Any]) -> list[str]:
    return profile_values(name, profile, "code_path", "code_paths")


def require_global_paths(config: dict[str, Any]) -> tuple[Path, Path]:
    globals_ = config["globals"]
    missing = [name for name in ("path_base", "path_strix") if not globals_.get(name)]
    if missing:
        raise UserError("Falta configurar: " + ", ".join(missing))
    return (
        Path(os.path.expandvars(globals_["path_base"])).expanduser(),
        Path(os.path.expandvars(globals_["path_strix"])).expanduser(),
    )


def validate_profile(name: str, profile: Any) -> None:
    if not isinstance(profile, dict):
        raise UserError(f"El perfil {name!r} debe ser un objeto JSON.")
    urls = profile_urls(name, profile)
    code_paths = profile_code_paths(name, profile)
    if not urls and not code_paths:
        raise UserError(
            f"El perfil {name!r} necesita al menos una URL o una ruta de código."
        )
    for url in urls:
        validate_url(url)
    workspace_files = profile.get("workspace_files", [])
    if not isinstance(workspace_files, list) or not all(
        isinstance(item, str) for item in workspace_files
    ):
        raise UserError(f"workspace_files de {name!r} debe ser una lista de textos.")
    for key in (
        "code_path",
        "instruction_file",
        "additional_instruction_file",
        "scan_mode",
        "start_command",
        "stop_command",
        "command_cwd",
    ):
        if profile.get(key) is not None and not isinstance(profile[key], str):
            raise UserError(f"{key} de {name!r} debe ser texto.")
    if profile.get("additional_instruction_file") is not None and not profile[
        "additional_instruction_file"
    ].strip():
        raise UserError(
            f"additional_instruction_file de {name!r} no puede estar vacío."
        )
    has_project_command = profile.get("start_command") or profile.get("stop_command")
    if has_project_command and not code_paths and not profile.get("command_cwd"):
        raise UserError(
            f"El perfil {name!r} necesita una ruta de código o command_cwd para "
            "usar comandos de arranque o parada."
        )
    if has_project_command and len(code_paths) > 1 and not profile.get("command_cwd"):
        raise UserError(
            f"El perfil {name!r} tiene varios code_paths; configura command_cwd "
            "para los comandos de arranque y parada."
        )
    start_wait = profile.get("start_wait_seconds", 5.0)
    if not isinstance(start_wait, (int, float)) or start_wait < 0:
        raise UserError(f"start_wait_seconds de {name!r} debe ser un número positivo.")
    stop_grace = profile.get("stop_grace_seconds", 10.0)
    if not isinstance(stop_grace, (int, float)) or stop_grace < 0:
        raise UserError(f"stop_grace_seconds de {name!r} debe ser un número positivo.")
    extra_args = profile.get("extra_args", [])
    if not isinstance(extra_args, list) or not all(
        isinstance(item, str) for item in extra_args
    ):
        raise UserError(f"extra_args de {name!r} debe ser una lista de textos.")


def validate_config(config: dict[str, Any]) -> None:
    """Validate persisted configuration before any command consumes it."""
    globals_ = config["globals"]
    for key in ("path_base", "path_strix", "log_dir"):
        value = globals_.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise UserError(f"{key} debe ser una ruta de texto no vacía.")
    for name, profile in config["applications"].items():
        if not isinstance(name, str) or not name.strip():
            raise UserError("Cada aplicación debe tener un nombre de texto no vacío.")
        validate_profile(name, profile)


def build_command(
    config: dict[str, Any],
    name: str,
    *,
    code_mode: str = "auto",
    target_mode: str | None = None,
    non_interactive: bool = False,
) -> tuple[list[str], Path]:
    path_base, path_strix = require_global_paths(config)
    try:
        profile = config["applications"][name]
    except KeyError as exc:
        raise UserError(f"No existe la aplicación {name!r}.") from exc
    validate_profile(name, profile)

    if target_mode is None:
        target_mode = "pentesting" if code_mode == "exclude" else "all"
    if target_mode not in {"all", "code", "pentesting"}:
        raise UserError(f"Modo de objetivos no válido: {target_mode!r}")

    command = ["uv", "run", "strix"]
    if non_interactive:
        command.append("--non-interactive")
    urls = profile_urls(name, profile)
    if target_mode == "code" and not profile_code_paths(name, profile):
        raise UserError(f"{name!r} no tiene rutas de código configuradas.")
    if target_mode == "pentesting" and not urls:
        raise UserError(f"{name!r} no tiene URL configuradas para pentesting.")
    if target_mode != "code":
        for url in urls:
            command.extend(["--target", url])

    code_paths = profile_code_paths(name, profile)
    if code_mode == "include" and not code_paths:
        raise UserError(f"{name!r} no tiene rutas de código configuradas.")
    if target_mode != "pentesting":
        for code_path in code_paths:
            command.extend(["--target", str(resolve_from(path_base, code_path))])
    if "--target" not in command:
        raise UserError(
            f"{name!r} se quedaría sin objetivos: no tiene URL y se ha excluido el código."
        )

    instruction_file = profile.get("instruction_file")
    if instruction_file:
        command.extend(
            ["--instruction-file", str(resolve_from(path_base, instruction_file))]
        )
    for workspace_file in profile.get("workspace_files", []):
        command.extend(
            ["--workspace-file", str(resolve_from(path_base, workspace_file))]
        )
    if profile.get("scan_mode"):
        command.extend(["--scan-mode", profile["scan_mode"]])
    command.extend(profile.get("extra_args", []))
    return command, path_strix


def validate_runtime_paths(
    config: dict[str, Any],
    name: str,
    command: Sequence[str],
    cwd: Path,
    *,
    ignore_configured_additional: bool = False,
) -> None:
    path_base, _ = require_global_paths(config)
    profile = config["applications"][name]
    if not cwd.is_dir():
        raise UserError(f"PATH_STRIX no es un directorio: {cwd}")
    candidates: list[tuple[str, str]] = []
    if profile.get("instruction_file"):
        candidates.append(("instruction_file", profile["instruction_file"]))
    if profile.get("additional_instruction_file") and not ignore_configured_additional:
        candidates.append(
            (
                "additional_instruction_file",
                profile["additional_instruction_file"],
            )
        )
    candidates.extend(("workspace_file", item) for item in profile.get("workspace_files", []))
    for label, raw_path in candidates:
        path = resolve_from(path_base, raw_path)
        if not path.is_file():
            raise UserError(f"No existe {label} para {name!r}: {path}")
    for raw_code_path in profile_code_paths(name, profile):
        code_path = resolve_from(path_base, raw_code_path)
        if str(code_path) in command and not code_path.exists():
            raise UserError(f"No existe una ruta de código para {name!r}: {code_path}")


def project_command(
    config: dict[str, Any], name: str, field: str
) -> tuple[list[str], Path] | None:
    """Return a configured start/stop command and its code working directory."""
    path_base, _ = require_global_paths(config)
    profile = config["applications"][name]
    raw_command = profile.get(field)
    if not raw_command:
        return None
    raw_cwd = profile.get("command_cwd")
    if raw_cwd:
        command_path = resolve_from(path_base, raw_cwd)
    else:
        code_paths = profile_code_paths(name, profile)
        if len(code_paths) != 1:
            raise UserError(
                f"{name!r} necesita command_cwd para ejecutar {field} con "
                "varias rutas de código."
            )
        command_path = resolve_from(path_base, code_paths[0])
    if not command_path.exists():
        raise UserError(f"No existe command_cwd para {name!r}: {command_path}")
    cwd = command_path if command_path.is_dir() else command_path.parent
    try:
        command = shlex.split(raw_command)
    except ValueError as exc:
        raise UserError(f"{field} no se puede interpretar para {name!r}: {exc}") from exc
    if not command:
        raise UserError(f"{field} está vacío para {name!r}.")
    return command, cwd


def wait_for_startup(process: subprocess.Popen[Any], seconds: float, name: str) -> None:
    """Wait briefly for startup and fail if the command exits unsuccessfully."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            if return_code != 0:
                raise UserError(
                    f"El comando de arranque de {name!r} terminó con código {return_code}."
                )
            return  # A successful short-lived command may have daemonized the service.
        time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))


def stop_project(
    managed: ManagedProcess | None,
    stop_spec: tuple[list[str], Path] | None,
    name: str,
    output: BinaryIO | None = None,
    grace_seconds: float = 10.0,
) -> None:
    """Run optional cleanup and always try to terminate the managed process tree."""
    try:
        if stop_spec is not None:
            stop_command, stop_cwd = stop_spec
            print(f"[{name}] parada: {shlex.join(stop_command)}")
            if output is not None:
                write_log_event(
                    output,
                    "STOP",
                    stop_command,
                    stop_cwd,
                )
            try:
                run_options: dict[str, Any] = {}
                if output is not None:
                    run_options.update(stdout=output, stderr=subprocess.STDOUT)
                result = subprocess.run(
                    stop_command,
                    cwd=stop_cwd,
                    check=False,
                    stdin=subprocess.DEVNULL,
                    timeout=max(1.0, grace_seconds),
                    **run_options,
                )
            except subprocess.TimeoutExpired:
                print(
                    f"[{name}] El comando de parada superó "
                    f"{max(1.0, grace_seconds):g} segundos.",
                    file=sys.stderr,
                )
            except OSError as exc:
                print(
                    f"[{name}] No se pudo ejecutar el comando de parada: {exc}",
                    file=sys.stderr,
                )
            else:
                if result.returncode != 0:
                    print(
                        f"[{name}] El comando de parada terminó con código "
                        f"{result.returncode}.",
                        file=sys.stderr,
                    )
    finally:
        terminate_process_tree(managed, name, grace_seconds, output)


def terminate_process_tree(
    managed: ManagedProcess | None,
    name: str,
    grace_seconds: float = 10.0,
    output: BinaryIO | None = None,
) -> None:
    """Best-effort termination of a process and the children in its process group."""
    if managed is None:
        return
    process = managed.process
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode != 0 and process.poll() is None:
                process.kill()
            if process.poll() is None:
                process.wait(timeout=max(1.0, grace_seconds))
            return

        group_id = managed.group_id
        if group_id is None or group_id <= 1 or group_id == os.getpgrp():
            print(
                f"[{name}] Grupo de procesos inseguro ({group_id}); "
                "solo se finalizará el proceso padre.",
                file=sys.stderr,
            )
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=max(1.0, grace_seconds))
            return

        write_process_lifecycle_event(output, "TERM", process.pid, group_id)
        os.killpg(group_id, signal.SIGTERM)
        deadline = time.monotonic() + grace_seconds
        while time.monotonic() < deadline:
            process.poll()  # Reap the group leader when it exits.
            if not process_group_exists(group_id):
                return
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
        process.poll()
        if process_group_exists(group_id):
            write_process_lifecycle_event(output, "KILL", process.pid, group_id)
            os.killpg(group_id, signal.SIGKILL)
        if process.poll() is None:
            process.wait(timeout=1)
    except ProcessLookupError:
        return
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=1)
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"[{name}] No se pudo forzar la parada: {exc}", file=sys.stderr)
    except OSError as exc:
        print(f"[{name}] No se pudo finalizar el proceso iniciado: {exc}", file=sys.stderr)
        try:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        except (OSError, subprocess.SubprocessError) as fallback_exc:
            print(
                f"[{name}] Tampoco se pudo finalizar el proceso padre: "
                f"{fallback_exc}",
                file=sys.stderr,
            )


def process_group_exists(group_id: int) -> bool:
    """Return whether a POSIX process group still has at least one member."""
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def write_process_lifecycle_event(
    output: BinaryIO | None,
    event: str,
    pid: int,
    group_id: int | None,
) -> None:
    if output is None:
        return
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    output.write(
        f"\n[{timestamp}] PROCESS_{event} pid={pid} pgid={group_id}\n".encode("utf-8")
    )
    output.flush()


def start_managed_process(
    command: Sequence[str],
    cwd: Path,
    output: BinaryIO | None,
) -> ManagedProcess:
    """Start an application without terminal input in an isolated process group."""
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=output,
        stderr=subprocess.STDOUT,
        **start_process_options(),
    )
    group_id: int | None = None
    if os.name != "nt":
        try:
            group_id = os.getpgid(process.pid)
        except OSError:
            # start_new_session makes the child PID its PGID before exec. If the
            # command exits during lookup, retaining that identity still lets
            # cleanup find any children it left in the group.
            group_id = process.pid
    write_process_lifecycle_event(output, "START", process.pid, group_id)
    return ManagedProcess(process, group_id)


def start_process_options() -> dict[str, Any]:
    """Return platform-specific options for creating a terminable process group."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def log_root(config: dict[str, Any], override: Path | None = None) -> Path:
    """Resolve the configured log root or a per-run command-line override."""
    if override is not None:
        expanded = Path(os.path.expandvars(str(override))).expanduser()
        return expanded if expanded.is_absolute() else Path.cwd() / expanded
    configured = config["globals"].get("log_dir")
    if configured:
        path_base, _ = require_global_paths(config)
        return resolve_from(path_base, configured)
    return DEFAULT_LOG_DIR


def new_log_run_id() -> str:
    return datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%f%z")


def safe_profile_directory(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-") or "profile"
    if safe == name:
        return safe
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:8]
    return f"{safe}-{digest}"


def application_log_path(
    config: dict[str, Any],
    name: str,
    run_id: str,
    override: Path | None = None,
) -> Path:
    return log_root(config, override) / run_id / safe_profile_directory(name) / "application.log"


def create_private_directories(path: Path) -> None:
    """Create missing directories and restrict only directories created here."""
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        for directory in missing:
            os.chmod(directory, 0o700)
    except OSError as exc:
        raise UserError(f"No se pudo crear el directorio de logs {path}: {exc}") from exc


def write_log_event(
    output: BinaryIO,
    event: str,
    command: Sequence[str],
    cwd: Path,
) -> None:
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    header = (
        f"\n[{timestamp}] {event}\n"
        f"cwd: {cwd}\n"
        f"command: {shlex.join(command)}\n"
        "--- output ---\n"
    )
    output.write(header.encode("utf-8"))
    output.flush()


@contextmanager
def application_log(path: Path, name: str) -> Iterator[BinaryIO]:
    """Create and close an owner-only binary application log."""
    create_private_directories(path.parent)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise UserError(f"El log de aplicación ya existe: {path}") from exc
    except OSError as exc:
        raise UserError(f"No se pudo crear el log de aplicación {path}: {exc}") from exc
    try:
        os.chmod(path, 0o600)
        with os.fdopen(fd, "wb", buffering=0) as output:
            timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
            output.write(
                (
                    f"Strix Runner application log\n"
                    f"profile: {name}\n"
                    f"created: {timestamp}\n"
                ).encode("utf-8")
            )
            yield output
    except Exception:
        # os.fdopen owns fd after it succeeds; otherwise close the raw descriptor.
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def strix_runs_root(cwd: Path) -> Path:
    """Return the canonical Strix artifact directory for a command cwd."""
    return (cwd / STRIX_RUNS_DIRECTORY).resolve()


def snapshot_strix_runs(cwd: Path) -> dict[Path, StrixRunSnapshot]:
    """Snapshot run.json files without trusting directory names as paths."""
    root = strix_runs_root(cwd)
    if not root.is_dir():
        return {}
    snapshot: dict[Path, StrixRunSnapshot] = {}
    try:
        children = list(root.iterdir())
    except OSError:
        return snapshot
    for child in children:
        try:
            run_dir = child.resolve()
            run_dir.relative_to(root)
            record = run_dir / STRIX_RUN_RECORD
            stat = record.stat()
        except (OSError, ValueError):
            continue
        if record.is_file():
            snapshot[run_dir] = StrixRunSnapshot(stat.st_mtime_ns, stat.st_size)
    return snapshot


def read_json_artifact(path: Path, maximum_bytes: int) -> Any | None:
    """Best-effort bounded JSON reader for artifacts produced by Strix."""
    try:
        if path.stat().st_size > maximum_bytes:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def command_targets(command: Sequence[str]) -> list[str]:
    """Extract every --target value from a generated Strix command."""
    return [
        command[index + 1]
        for index, argument in enumerate(command[:-1])
        if argument == "--target"
    ]


def record_targets(record: dict[str, Any]) -> list[str]:
    targets = record.get("targets_info")
    if not isinstance(targets, list):
        return []
    return [
        str(target["original"])
        for target in targets
        if isinstance(target, dict) and target.get("original") is not None
    ]


def comparable_history_target(value: str) -> str:
    """Normalize local paths while leaving URL semantics unchanged."""
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"}:
        return value
    return os.path.normcase(os.path.normpath(value))


def profile_target_variants(
    config: dict[str, Any], name: str
) -> tuple[frozenset[str], ...]:
    """Return target sets produced by all/code/pentesting modes."""
    path_base, _ = require_global_paths(config)
    profile = config["applications"][name]
    urls = [comparable_history_target(value) for value in profile_urls(name, profile)]
    code_paths = [
        comparable_history_target(str(resolve_from(path_base, value)))
        for value in profile_code_paths(name, profile)
    ]
    variants = []
    for values in (urls + code_paths, urls, code_paths):
        variant = frozenset(values)
        if variant and variant not in variants:
            variants.append(variant)
    return tuple(variants)


def match_history_profiles(
    config: dict[str, Any], targets: Sequence[str]
) -> tuple[list[str], str]:
    """Match persisted targets to current profiles without guessing silently."""
    expected = frozenset(comparable_history_target(value) for value in targets)
    if not expected:
        return [], "unmatched"

    variants = {
        name: profile_target_variants(config, name)
        for name in config["applications"]
    }
    exact = sorted(
        name for name, profile_variants in variants.items() if expected in profile_variants
    )
    if exact:
        return exact, "reconstructed" if len(exact) == 1 else "ambiguous"

    subset = sorted(
        name
        for name, profile_variants in variants.items()
        if profile_variants and expected < profile_variants[0]
    )
    if subset:
        return (
            subset,
            "reconstructed_subset" if len(subset) == 1 else "ambiguous",
        )
    return [], "unmatched"


def normalized_skill_audit_entry(value: Any) -> dict[str, Any] | None:
    """Validate one optional structured skill-utility record."""
    if not isinstance(value, dict):
        return None
    skill = clean_terminal_text(value.get("skill"), maximum=200)
    if not skill:
        return None
    rating = str(value.get("rating") or "not_observable").strip().lower()
    rating = rating.replace("-", "_").replace(" ", "_")
    if rating not in UTILITY_RATINGS:
        rating = "not_observable"
    evidence = value.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    return {
        "agent_id": clean_terminal_text(value.get("agent_id"), maximum=200),
        "agent_name": clean_terminal_text(value.get("agent_name"), maximum=200),
        "skill": skill,
        "rating": rating,
        "reason": clean_terminal_text(value.get("reason"), maximum=2_000) or None,
        "evidence": [
            clean_terminal_text(item, maximum=300)
            for item in evidence
            if clean_terminal_text(item, maximum=300)
        ],
    }


def load_skill_audit(
    run_dir: Path, runner_record: dict[str, Any] | None
) -> list[dict[str, Any]]:
    """Load explicit ratings only; never infer utility from agent conversations."""
    raw_entries: list[Any] = []
    if isinstance(runner_record, dict):
        stored = runner_record.get("skill_audit", [])
        if isinstance(stored, list):
            raw_entries.extend(stored)
    state_record = read_json_artifact(
        run_dir / ".state" / SKILL_AUDIT_RECORD,
        MAX_RUNNER_RECORD_BYTES,
    )
    if isinstance(state_record, list):
        raw_entries.extend(state_record)
    elif isinstance(state_record, dict) and isinstance(
        state_record.get("skills"), list
    ):
        raw_entries.extend(state_record["skills"])
    return [
        normalized
        for entry in raw_entries
        if (normalized := normalized_skill_audit_entry(entry)) is not None
    ]


def load_history_agents(
    run_dir: Path, runner_record: dict[str, Any] | None
) -> list[HistoryAgent]:
    """Read the compact Strix agent state without opening message transcripts."""
    state = read_json_artifact(
        run_dir / ".state" / "agents.json",
        MAX_AGENTS_STATE_BYTES,
    )
    if not isinstance(state, dict):
        return []
    statuses = state.get("statuses") if isinstance(state.get("statuses"), dict) else {}
    names = state.get("names") if isinstance(state.get("names"), dict) else {}
    metadata = state.get("metadata") if isinstance(state.get("metadata"), dict) else {}
    audits = load_skill_audit(run_dir, runner_record)
    audit_agent_ids = {
        entry["agent_id"] for entry in audits if entry.get("agent_id")
    }
    agent_ids = sorted(set(statuses) | set(names) | set(metadata) | audit_agent_ids)
    agents: list[HistoryAgent] = []
    for agent_id in agent_ids:
        raw_metadata = metadata.get(agent_id)
        if not isinstance(raw_metadata, dict):
            raw_metadata = {}
        agent_name = clean_terminal_text(names.get(agent_id), maximum=200) or agent_id
        raw_skills = raw_metadata.get("skills", [])
        if not isinstance(raw_skills, list):
            raw_skills = []
        skill_names: list[str] = []
        embedded_audits: list[dict[str, Any]] = []
        for raw_skill in raw_skills:
            if isinstance(raw_skill, str):
                skill_name = clean_terminal_text(raw_skill, maximum=200)
            elif isinstance(raw_skill, dict):
                skill_name = clean_terminal_text(
                    raw_skill.get("name") or raw_skill.get("skill"), maximum=200
                )
                normalized = normalized_skill_audit_entry(
                    {
                        **raw_skill,
                        "skill": skill_name,
                        "agent_id": agent_id,
                        "agent_name": agent_name,
                    }
                )
                if normalized is not None:
                    embedded_audits.append(normalized)
            else:
                skill_name = ""
            if skill_name and skill_name not in skill_names:
                skill_names.append(skill_name)

        relevant_audits = [
            entry
            for entry in audits + embedded_audits
            if entry.get("agent_id") == agent_id
            or (
                not entry.get("agent_id")
                and entry.get("agent_name") == agent_name
            )
        ]
        for entry in relevant_audits:
            if entry["skill"] not in skill_names:
                skill_names.append(entry["skill"])
        skills: list[HistorySkill] = []
        for skill_name in skill_names:
            audit = next(
                (
                    entry
                    for entry in relevant_audits
                    if entry["skill"] == skill_name
                ),
                None,
            )
            skills.append(
                HistorySkill(
                    name=skill_name,
                    utility=audit["rating"] if audit else "not_observable",
                    reason=audit["reason"] if audit else None,
                    evidence=list(audit["evidence"]) if audit else [],
                )
            )
        agents.append(
            HistoryAgent(
                agent_id=agent_id,
                name=agent_name,
                status=clean_terminal_text(statuses.get(agent_id), maximum=80) or None,
                task=clean_terminal_text(raw_metadata.get("task"), maximum=2_000)
                or None,
                skills=skills,
            )
        )
    return agents


def reconstructed_history_command(
    record: dict[str, Any], targets: Sequence[str]
) -> tuple[list[str], list[str]]:
    """Reconstruct observable argv and explicitly identify missing arguments."""
    command = ["uv", "run", "strix"]
    if record.get("non_interactive") is True:
        command.append("--non-interactive")
    for target in targets:
        command.extend(["--target", target])
    gaps = ["extra_args"]
    if record.get("instruction"):
        command.extend(["--instruction-file", "<ruta-no-observable>"])
        gaps.append("instruction_file_path")
    workspace_files = record.get("workspace_files")
    if isinstance(workspace_files, list):
        for workspace_file in workspace_files:
            if not isinstance(workspace_file, dict):
                continue
            source_path = workspace_file.get("source_path")
            if isinstance(source_path, str) and source_path:
                command.extend(["--workspace-file", source_path])
    scan_mode = record.get("scan_mode")
    if isinstance(scan_mode, str) and scan_mode:
        command.extend(["--scan-mode", scan_mode])
    return command, gaps


def captured_history_command(
    runner_record: dict[str, Any] | None,
) -> tuple[list[str] | None, str | None]:
    if not isinstance(runner_record, dict):
        return None, None
    commands = runner_record.get("commands")
    if not isinstance(commands, dict):
        return None, None
    strix_command = commands.get("strix")
    if isinstance(strix_command, dict):
        argv = strix_command.get("argv")
        cwd = strix_command.get("cwd")
    else:
        argv = strix_command
        cwd = None
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return None, None
    return list(argv), str(cwd) if cwd else None


def history_report_uri(path: Path) -> str | None:
    try:
        return path.resolve().as_uri() if path.is_file() else None
    except (OSError, ValueError):
        return None


def build_history_run(config: dict[str, Any], run_dir: Path) -> HistoryRun | None:
    """Normalize one Strix directory into a stable history record."""
    record = read_json_artifact(run_dir / STRIX_RUN_RECORD, MAX_RUN_RECORD_BYTES)
    if not isinstance(record, dict):
        return None
    runner_record = read_json_artifact(
        run_dir / RUNNER_RUN_RECORD,
        MAX_RUNNER_RECORD_BYTES,
    )
    if not isinstance(runner_record, dict):
        runner_record = None
    targets = record_targets(record)
    captured_profile = (
        clean_terminal_text(runner_record.get("profile"), maximum=200)
        if runner_record
        else ""
    )
    if captured_profile:
        profile = captured_profile
        profile_candidates = [captured_profile]
        profile_source = "captured"
    else:
        profile_candidates, profile_source = match_history_profiles(config, targets)
        profile = profile_candidates[0] if len(profile_candidates) == 1 else None

    vulnerabilities = read_json_artifact(
        run_dir / "vulnerabilities.json",
        MAX_VULNERABILITIES_BYTES,
    )
    severity_counts = {
        severity: 0 for severity in ("critical", "high", "medium", "low", "info")
    }
    if isinstance(vulnerabilities, list):
        findings: int | None = len(vulnerabilities)
        findings_source = "captured"
        for finding in vulnerabilities:
            severity = (
                str(finding.get("severity") or "").strip().lower()
                if isinstance(finding, dict)
                else ""
            )
            if severity in severity_counts:
                severity_counts[severity] += 1
            elif severity:
                severity_counts["unknown"] = severity_counts.get("unknown", 0) + 1
    else:
        findings = None
        findings_source = "not_observable"

    command, command_cwd = captured_history_command(runner_record)
    if command is None:
        command, command_gaps = reconstructed_history_command(record, targets)
        command_source = "reconstructed"
    else:
        command_gaps = []
        command_source = "captured"
    command_display = shlex.join(command)
    if command_cwd:
        command_display = f"(cwd={command_cwd}) {command_display}"

    llm_usage_record = record.get("llm_usage")
    llm_usage: dict[str, int | float] = {}
    if isinstance(llm_usage_record, dict):
        for key in ("requests", "input_tokens", "output_tokens", "total_tokens", "cost"):
            value = llm_usage_record.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                llm_usage[key] = value

    start_time = clean_terminal_text(record.get("start_time"), maximum=80) or None
    end_time = clean_terminal_text(record.get("end_time"), maximum=80) or None
    date_source = "captured"
    if start_time is None:
        try:
            start_time = datetime.fromtimestamp(
                run_dir.stat().st_mtime
            ).astimezone().isoformat(timespec="seconds")
            date_source = "filesystem"
        except OSError:
            date_source = "not_observable"
    report_path = run_dir / "penetration_test_report.md"
    return HistoryRun(
        selection_id=0,
        run_id=clean_terminal_text(record.get("run_id"), maximum=200) or None,
        run_name=clean_terminal_text(record.get("run_name"), maximum=200)
        or run_dir.name,
        run_dir=str(run_dir),
        profile=profile,
        profile_source=profile_source,
        profile_candidates=profile_candidates,
        start_time=start_time,
        end_time=end_time,
        date_source=date_source,
        status=clean_terminal_text(record.get("status"), maximum=80) or "unknown",
        scan_mode=clean_terminal_text(record.get("scan_mode"), maximum=80) or None,
        duration_seconds=elapsed_seconds(start_time, end_time),
        targets=targets,
        findings=findings,
        severity_counts=severity_counts,
        findings_source=findings_source,
        report_path=str(report_path) if report_path.is_file() else None,
        report_uri=history_report_uri(report_path),
        command=command,
        command_display=command_display,
        command_source=command_source,
        command_gaps=command_gaps,
        agents=load_history_agents(run_dir, runner_record),
        llm_usage=llm_usage,
    )


def parse_history_date(value: str, label: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise UserError(f"{label} debe tener formato AAAA-MM-DD: {value!r}.") from exc


def history_run_date(run: HistoryRun) -> date | None:
    if not run.start_time:
        return None
    try:
        return datetime.fromisoformat(run.start_time.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def history_sort_key(run: HistoryRun) -> float:
    if run.start_time:
        try:
            return datetime.fromisoformat(
                run.start_time.replace("Z", "+00:00")
            ).timestamp()
        except (OSError, ValueError):
            pass
    try:
        return Path(run.run_dir).stat().st_mtime
    except OSError:
        return 0.0


def collect_history_runs(
    config: dict[str, Any],
    *,
    profile: str | None = None,
    from_date: date | None = None,
    to_date: date | None = None,
    run_selector: str | None = None,
) -> list[HistoryRun]:
    """Collect safe, bounded history records and apply user filters."""
    _, path_strix = require_global_paths(config)
    root = strix_runs_root(path_strix)
    if not root.is_dir():
        raise UserError(f"No existe el directorio de ejecuciones de Strix: {root}")
    try:
        children = list(root.iterdir())
    except OSError as exc:
        raise UserError(f"No se pudo recorrer {root}: {exc}") from exc

    runs: list[HistoryRun] = []
    for child in children:
        try:
            run_dir = child.resolve()
            run_dir.relative_to(root)
        except (OSError, ValueError):
            continue
        if not run_dir.is_dir() or not (run_dir / STRIX_RUN_RECORD).is_file():
            continue
        run = build_history_run(config, run_dir)
        if run is None:
            continue
        if profile and profile not in run.profile_candidates:
            continue
        run_date = history_run_date(run)
        if from_date and (run_date is None or run_date < from_date):
            continue
        if to_date and (run_date is None or run_date > to_date):
            continue
        runs.append(run)
    runs = sorted(runs, key=history_sort_key, reverse=True)
    for selection_id, run in enumerate(runs, start=1):
        run.selection_id = selection_id
    if run_selector:
        selector = run_selector.strip()
        if selector.isdecimal():
            selection_id = int(selector)
            if selection_id < 1 or selection_id > len(runs):
                raise UserError(f"ID de ejecución fuera de rango: {selection_id}.")
            return [runs[selection_id - 1]]
        runs = [
            run
            for run in runs
            if selector in {run.run_id, run.run_name, Path(run.run_dir).name}
        ]
    return runs


def locate_changed_strix_run(
    cwd: Path,
    before: dict[Path, StrixRunSnapshot],
    expected_targets: Sequence[str],
) -> tuple[Path | None, dict[str, Any] | None, str | None]:
    """Correlate one changed Strix run with the targets of the launched profile."""
    after = snapshot_strix_runs(cwd)
    changed = [run_dir for run_dir, state in after.items() if before.get(run_dir) != state]
    candidates: list[tuple[Path, dict[str, Any]]] = []
    for run_dir in changed:
        record = read_json_artifact(
            run_dir / STRIX_RUN_RECORD,
            MAX_RUN_RECORD_BYTES,
        )
        if isinstance(record, dict):
            candidates.append((run_dir, record))

    expected = sorted(str(target) for target in expected_targets)
    exact = [item for item in candidates if sorted(record_targets(item[1])) == expected]
    if len(exact) == 1:
        return exact[0][0], exact[0][1], None
    if len(exact) > 1:
        return None, None, "Varias ejecuciones de Strix coinciden con los objetivos."
    if not candidates:
        return None, None, "Strix no generó un run.json nuevo o actualizado."
    return None, None, "Los artefactos modificados no coinciden con los objetivos ejecutados."


def clean_terminal_text(value: Any, *, maximum: int | None = None) -> str:
    """Remove terminal controls from report text before displaying or persisting it."""
    text = ANSI_ESCAPE_RE.sub("", str(value or ""))
    text = "".join(
        character
        for character in text
        if character in {"\n", "\t"} or ord(character) >= 32
    ).strip()
    if maximum is not None and len(text) > maximum:
        return text[:maximum].rstrip() + "…"
    return text


def elapsed_seconds(started_at: Any, ended_at: Any) -> float | None:
    try:
        start = datetime.fromisoformat(str(started_at).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(ended_at).replace("Z", "+00:00"))
        return max(0.0, (end - start).total_seconds())
    except (TypeError, ValueError):
        return None


def build_execution_result(
    profile: str,
    returncode: int,
    run_dir: Path | None,
    record: dict[str, Any] | None,
    correlation_error: str | None,
    fallback_duration: float,
) -> ExecutionResult:
    """Build a stable runner result from Strix's persisted public artifacts."""
    if run_dir is None or record is None:
        return ExecutionResult(
            profile=profile,
            returncode=returncode,
            outcome="ERROR" if returncode else "SIN INFORME",
            duration_seconds=fallback_duration,
            error=correlation_error,
        )

    vulnerabilities = read_json_artifact(
        run_dir / "vulnerabilities.json",
        MAX_VULNERABILITIES_BYTES,
    )
    reports = vulnerabilities if isinstance(vulnerabilities, list) else []
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    unknown = 0
    for report in reports:
        severity = (
            str(report.get("severity") or "").strip().lower()
            if isinstance(report, dict)
            else ""
        )
        if severity in counts:
            counts[severity] += 1
        else:
            unknown += 1
    if unknown:
        counts["unknown"] = unknown

    strix_status = clean_terminal_text(record.get("status"), maximum=40) or "unknown"
    scan_results = record.get("scan_results")
    has_final_report = isinstance(scan_results, dict)
    if strix_status == "completed" and has_final_report:
        outcome = "COMPLETADA CON HALLAZGOS" if reports else "COMPLETADA"
    elif strix_status == "failed":
        outcome = "ERROR"
    elif strix_status in {"stopped", "interrupted", "running"} or not has_final_report:
        outcome = "INCOMPLETA"
    else:
        outcome = "DESCONOCIDA"

    executive_summary = None
    if isinstance(scan_results, dict):
        executive_summary = clean_terminal_text(
            scan_results.get("executive_summary"),
            maximum=100_000,
        ) or None
    report_path = run_dir / "penetration_test_report.md"
    return ExecutionResult(
        profile=profile,
        returncode=returncode,
        outcome=outcome,
        strix_status=strix_status,
        run_name=run_dir.name,
        run_dir=str(run_dir),
        report_path=str(report_path) if report_path.is_file() else None,
        started_at=clean_terminal_text(record.get("start_time"), maximum=80) or None,
        ended_at=clean_terminal_text(record.get("end_time"), maximum=80) or None,
        duration_seconds=(
            elapsed_seconds(record.get("start_time"), record.get("end_time"))
            or fallback_duration
        ),
        findings=len(reports),
        severity_counts=counts,
        executive_summary=executive_summary,
        error=(
            "Strix terminó sin generar el informe final."
            if not has_final_report
            else None
        ),
    )


def execute_application_with_report(
    config: dict[str, Any], name: str, args: argparse.Namespace
) -> ExecutionResult:
    """Execute one profile and correlate the public artifacts written by Strix."""
    command, cwd = build_command(
        config,
        name,
        code_mode=getattr(args, "code_mode", "auto"),
        target_mode=getattr(args, "target_mode", None),
        non_interactive=getattr(args, "non_interactive", False),
    )
    for attribute in (
        "observed_strix_command",
        "observed_strix_cwd",
        "observed_start_spec",
        "observed_stop_spec",
    ):
        setattr(args, attribute, None)
    if getattr(args, "dry_run", False):
        returncode = run_application(config, name, args)
        return ExecutionResult(name, returncode, "SIMULADA")

    before = snapshot_strix_runs(cwd)
    started = time.monotonic()
    try:
        returncode = run_application(config, name, args)
    except KeyboardInterrupt as exc:
        duration = max(0.0, time.monotonic() - started)
        run_dir, record, error = locate_changed_strix_run(
            cwd,
            before,
            command_targets(command),
        )
        try_save_runner_run_record(
            run_dir,
            config,
            name,
            args,
            command,
            cwd,
        )
        interrupted = build_execution_result(
            name,
            130,
            run_dir,
            record,
            error,
            duration,
        )
        if interrupted.outcome not in {"INCOMPLETA", "ERROR"}:
            interrupted.outcome = "INCOMPLETA"
        interrupted.error = interrupted.error or "Ejecución interrumpida por el usuario."
        raise ApplicationInterrupted(interrupted) from exc
    duration = max(0.0, time.monotonic() - started)
    run_dir, record, error = locate_changed_strix_run(
        cwd,
        before,
        command_targets(command),
    )
    try_save_runner_run_record(
        run_dir,
        config,
        name,
        args,
        command,
        cwd,
    )
    return build_execution_result(
        name,
        returncode,
        run_dir,
        record,
        error,
        duration,
    )


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "-"
    total = max(0, int(round(seconds)))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:d}h {minutes:02d}m {secs:02d}s" if hours else f"{minutes:d}m {secs:02d}s"


def format_severity_counts(counts: dict[str, int]) -> str:
    parts = [f"{severity}: {count}" for severity, count in counts.items() if count]
    return ", ".join(parts) if parts else "ninguno"


def print_execution_result(result: ExecutionResult, summary_mode: str) -> None:
    print(f"\n[{result.profile}] RESULTADO STRIX")
    print(f"Estado: {result.outcome}")
    strix_status = result.strix_status or "no identificado"
    print(
        f"Strix: {strix_status} | código: {result.returncode} | "
        f"duración: {format_duration(result.duration_seconds)}"
    )
    print(
        f"Hallazgos: {result.findings} "
        f"({format_severity_counts(result.severity_counts)})"
    )
    if summary_mode != "none" and result.executive_summary:
        maximum = SUMMARY_PREVIEW_CHARS if summary_mode == "short" else None
        print("\nResumen ejecutivo:")
        print(clean_terminal_text(result.executive_summary, maximum=maximum))
    if result.report_path:
        print(f"Informe: {result.report_path}")
    elif result.run_dir:
        print(f"Artefactos parciales: {result.run_dir}")
    if result.error:
        print(f"Nota: {clean_terminal_text(result.error, maximum=500)}")


def print_final_execution_summary(results: Sequence[ExecutionResult]) -> None:
    print("\nRESUMEN DE LA EJECUCIÓN")
    if not results:
        print("No se ejecutó ningún perfil.")
        return
    profile_width = max(len("Aplicación"), *(len(result.profile) for result in results))
    outcome_width = max(len("Estado"), *(len(result.outcome) for result in results))
    print(
        f"{'Aplicación':<{profile_width}}  {'Estado':<{outcome_width}}  "
        f"Hallazgos  Duración"
    )
    print(f"{'-' * profile_width}  {'-' * outcome_width}  ---------  --------")
    for result in results:
        print(
            f"{result.profile:<{profile_width}}  {result.outcome:<{outcome_width}}  "
            f"{result.findings:>9}  {format_duration(result.duration_seconds)}"
        )
    completed = sum(result.outcome.startswith("COMPLETADA") for result in results)
    incomplete = sum(result.outcome == "INCOMPLETA" for result in results)
    errors = sum(result.outcome == "ERROR" for result in results)
    without_report = sum(
        result.outcome in {"SIN INFORME", "DESCONOCIDA"} for result in results
    )
    simulated = sum(result.outcome == "SIMULADA" for result in results)
    findings = sum(result.findings for result in results)
    totals = [
        f"Completadas: {completed}",
        f"Incompletas: {incomplete}",
        f"Sin informe: {without_report}",
        f"Errores: {errors}",
    ]
    if simulated:
        totals.append(f"Simuladas: {simulated}")
    totals.append(f"Hallazgos: {findings}")
    print("\n" + " | ".join(totals))


def atomic_private_text(path: Path, payload: str) -> None:
    create_private_directories(path.parent)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(payload)
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def serialized_command_spec(value: Any) -> dict[str, Any] | None:
    """Convert an observed ``(argv, cwd)`` tuple into private JSON metadata."""
    if (
        not isinstance(value, tuple)
        or len(value) != 2
        or not isinstance(value[0], (list, tuple))
    ):
        return None
    argv, cwd = value
    if not all(isinstance(item, str) for item in argv):
        return None
    return {"argv": list(argv), "cwd": str(cwd)}


def save_runner_run_record(
    run_dir: Path,
    config: dict[str, Any],
    name: str,
    args: argparse.Namespace,
    logical_command: Sequence[str],
    cwd: Path,
) -> Path:
    """Persist runner provenance next to a Strix run with private permissions."""
    observed_command = getattr(args, "observed_strix_command", None)
    if not isinstance(observed_command, list) or not all(
        isinstance(item, str) for item in observed_command
    ):
        observed_command = list(logical_command)
    observed_cwd = getattr(args, "observed_strix_cwd", None) or cwd
    profile = config["applications"][name]
    additional_path = additional_instruction_path(
        config,
        name,
        getattr(args, "additional_instruction_file", None),
    )
    payload = {
        "schema_version": 1,
        "runner_version": __version__,
        "captured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "profile": name,
        "commands": {
            "strix": {
                "argv": observed_command,
                "cwd": str(observed_cwd),
            },
            "strix_logical": {
                "argv": list(logical_command),
                "cwd": str(cwd),
            },
            "start": serialized_command_spec(
                getattr(args, "observed_start_spec", None)
            ),
            "stop": serialized_command_spec(
                getattr(args, "observed_stop_spec", None)
            ),
        },
        "options": {
            "target_mode": getattr(args, "target_mode", None),
            "code_mode": getattr(args, "code_mode", "auto"),
            "non_interactive": bool(getattr(args, "non_interactive", False)),
        },
        "instruction_sources": {
            "configured": profile.get("instruction_file"),
            "additional": str(additional_path) if additional_path else None,
        },
        "skill_audit": [],
    }
    destination = run_dir / RUNNER_RUN_RECORD
    atomic_private_text(
        destination,
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    )
    return destination


def try_save_runner_run_record(
    run_dir: Path | None,
    config: dict[str, Any],
    name: str,
    args: argparse.Namespace,
    logical_command: Sequence[str],
    cwd: Path,
) -> None:
    if run_dir is None:
        return
    try:
        save_runner_run_record(run_dir, config, name, args, logical_command, cwd)
    except (OSError, UserError, TypeError, ValueError) as exc:
        print(
            f"[{name}] No se pudo guardar la procedencia del runner: {exc}",
            file=sys.stderr,
        )


def history_payload(
    runs: Sequence[HistoryRun],
    *,
    profile: str | None,
    from_date: date | None,
    to_date: date | None,
) -> dict[str, Any]:
    """Build the common data model used by JSON and standalone HTML."""
    findings = sum(run.findings or 0 for run in runs)
    unknown_findings = sum(run.findings is None for run in runs)
    agent_count = sum(len(run.agents) for run in runs)
    skill_count = sum(
        len(agent.skills) for run in runs for agent in run.agents
    )
    total_tokens = sum(
        int(run.llm_usage.get("total_tokens", 0)) for run in runs
    )
    return {
        "schema_version": 1,
        "runner_version": __version__,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "filters": {
            "profile": profile,
            "from": from_date.isoformat() if from_date else None,
            "to": to_date.isoformat() if to_date else None,
        },
        "summary": {
            "runs": len(runs),
            "findings": findings,
            "runs_with_unknown_findings": unknown_findings,
            "agents": agent_count,
            "skills": skill_count,
            "total_tokens": total_tokens,
        },
        "runs": [asdict(run) for run in runs],
    }


def history_profile_label(run: HistoryRun) -> str:
    if run.profile:
        return run.profile
    if run.profile_candidates:
        return "ambigua: " + ", ".join(run.profile_candidates)
    return "sin asociar"


def history_utility_label(value: str) -> str:
    return {
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "not_observable": "No observable",
    }.get(value, "No observable")


def print_history_runs(runs: Sequence[HistoryRun], *, details: bool) -> None:
    """Print a compact chronological table and optional per-agent detail."""
    if not runs:
        print("No se encontraron ejecuciones con los filtros indicados.")
        return
    profile_width = max(
        len("Aplicaci�n"),
        *(len(history_profile_label(run)) for run in runs),
    )
    id_width = max(len("ID"), len(str(len(runs))))
    status_width = max(len("Estado"), *(len(run.status) for run in runs))
    print(f"{'ID':>{id_width + 2}} ", end="")
    print(
        f"{'Fecha':<25}  {'Aplicaci�n':<{profile_width}}  "
        f"{'Estado':<{status_width}}  Hallazgos  Agentes  Skills"
    )
    print(f"{'-' * (id_width + 2)} ", end="")
    print(
        f"{'-' * 25}  {'-' * profile_width}  {'-' * status_width}  "
        "---------  -------  ------"
    )
    for run in runs:
        finding_text = "?" if run.findings is None else str(run.findings)
        skills = sum(len(agent.skills) for agent in run.agents)
        print(
            f"[{run.selection_id:>{id_width}}] "
            f"{(run.start_time or '-')[:25]:<25}  "
            f"{history_profile_label(run):<{profile_width}}  "
            f"{run.status:<{status_width}}  {finding_text:>9}  "
            f"{len(run.agents):>7}  {skills:>6}"
        )
        if not details:
            continue
        print(f"  ID: {run.selection_id} | Run: {run.run_id or run.run_name}")
        print(
            f"  Asociaci�n: {run.profile_source} | "
            f"Comando: {run.command_source}"
        )
        print(f"  {run.command_display}")
        if run.command_gaps:
            print("  No observable: " + ", ".join(run.command_gaps))
        if run.report_path:
            print(f"  Informe: {run.report_path}")
        for agent in run.agents:
            status = f" [{agent.status}]" if agent.status else ""
            print(f"  Agente: {agent.name}{status}")
            if agent.task:
                print(f"    Tarea: {agent.task}")
            if not agent.skills:
                print("    Skills: ninguna registrada")
            for skill in agent.skills:
                line = (
                    f"    - {skill.name}: "
                    f"{history_utility_label(skill.utility)}"
                )
                if skill.reason:
                    line += f" — {skill.reason}"
                print(line)
        print()


def standalone_history_html(payload: dict[str, Any]) -> str:
    """Render a dependency-free report that treats all artifact text as data."""
    embedded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    embedded = (
        embedded.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    template = """<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
  <title>Historial de Strix</title>
  <style>
    :root{color-scheme:dark;--bg:#0b1020;--panel:#151d31;--line:#2a3653;--text:#eef3ff;--muted:#9ba9c3;--accent:#79c7ff;--good:#5ee2a0;--warn:#ffd166;--bad:#ff718b}
    *{box-sizing:border-box}body{margin:0;background:linear-gradient(145deg,#09101f,#111a2e);color:var(--text);font:14px/1.45 system-ui,sans-serif}header,main{max-width:1280px;margin:auto;padding:24px}h1{margin:0 0 6px;font-size:30px}.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}.metric,.filters,.run{background:rgba(21,29,49,.94);border:1px solid var(--line);border-radius:12px}.metric{padding:16px}.metric strong{display:block;font-size:24px;color:var(--accent)}.filters{display:flex;flex-wrap:wrap;gap:12px;padding:16px;margin-bottom:18px}.filters label{display:grid;gap:5px;color:var(--muted)}input,select,button{background:#0e1628;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:8px 10px}button{cursor:pointer}button:hover{border-color:var(--accent)}#runs{display:grid;gap:12px}.run{overflow:hidden}.run summary{cursor:pointer;display:grid;grid-template-columns:minmax(190px,1.3fr) minmax(130px,1fr) minmax(90px,.6fr) repeat(3,minmax(60px,.45fr));gap:12px;align-items:center;padding:16px;list-style:none}.run summary::-webkit-details-marker{display:none}.run[open] summary{border-bottom:1px solid var(--line)}.detail{padding:18px;display:grid;gap:16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.box{background:#0e1628;border:1px solid var(--line);border-radius:9px;padding:13px}.box h3{margin:0 0 8px;font-size:14px;color:var(--accent)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080e1a;padding:12px;border-radius:7px;border:1px solid var(--line)}.badge{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:2px 8px;margin:2px 4px 2px 0;font-size:12px}.high{color:var(--good)}.medium{color:var(--warn)}.low{color:var(--bad)}.not_observable{color:var(--muted)}a{color:var(--accent)}@media(max-width:800px){.run summary{grid-template-columns:1fr 1fr}.optional{display:none}}
  </style>
</head>
<body>
<header><h1>Historial de Strix</h1><div id="generated" class="muted"></div><div id="metrics" class="cards"></div></header>
<main>
  <section class="filters">
    <label>Aplicaci�n<select id="profile"></select></label>
    <label>Estado<select id="status"></select></label>
    <label>Desde<input id="from" type="date"></label>
    <label>Hasta<input id="to" type="date"></label>
    <label>Buscar<input id="search" type="search" placeholder="run, agente o skill"></label>
    <label>Datos<button id="download" type="button">Descargar JSON</button></label>
  </section>
  <div id="count" class="muted"></div>
  <section id="runs"></section>
</main>
<script id="history-data" type="application/json">__PAYLOAD__</script>
<script>
const data=JSON.parse(document.getElementById('history-data').textContent);
const $=id=>document.getElementById(id);
const el=(tag,cls,text)=>{const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=String(text);return node};
const metric=(label,value)=>{const box=el('div','metric');box.append(el('strong','',value),el('span','muted',label));return box};
const formatNumber=value=>new Intl.NumberFormat('es-ES').format(value||0);
$('generated').textContent=`Generado ${data.generated_at} · runner ${data.runner_version}`;
const metrics=$('metrics');metrics.append(metric('Ejecuciones',data.summary.runs),metric('Hallazgos',data.summary.findings),metric('Agentes',data.summary.agents),metric('Skills cargadas',data.summary.skills),metric('Tokens',formatNumber(data.summary.total_tokens)));
const profiles=[...new Set(data.runs.flatMap(run=>run.profile_candidates.length?run.profile_candidates:['Sin asociar']))].sort();
const statuses=[...new Set(data.runs.map(run=>run.status))].sort();
const fill=(select,label,values)=>{select.append(new Option(label,''));values.forEach(value=>select.append(new Option(value,value)))};
fill($('profile'),'Todas',profiles);fill($('status'),'Todos',statuses);
if(data.filters.profile)$('profile').value=data.filters.profile;if(data.filters.from)$('from').value=data.filters.from;if(data.filters.to)$('to').value=data.filters.to;
const badge=(text,rating)=>el('span',`badge ${rating||''}`,text);
function addField(parent,title,value){const box=el('div','box');box.append(el('h3','',title),el('div','',value??'No observable'));parent.append(box)}
function renderRun(run){
  const details=el('details','run');const summary=el('summary');
  summary.append(el('strong','',`#${run.selection_id} - ${run.start_time||'Fecha no observable'}`),el('span','',run.profile||run.profile_candidates.join(', ')||'Sin asociar'),el('span','',run.status),el('span','optional',`${run.findings??'?'} hallazgos`),el('span','optional',`${run.agents.length} agentes`),el('span','optional',`${run.agents.reduce((n,a)=>n+a.skills.length,0)} skills`));details.append(summary);
  const body=el('div','detail');const overview=el('div','grid');addField(overview,'Run',run.run_id||run.run_name);addField(overview,'Asociaci�n',run.profile_source);addField(overview,'Duraci�n',run.duration_seconds==null?'No observable':`${Math.round(run.duration_seconds)} s`);addField(overview,'Tokens',formatNumber(run.llm_usage.total_tokens));body.append(overview);
  const command=el('div','box');command.append(el('h3','',`Comando · ${run.command_source}`),el('pre','',run.command_display));if(run.command_gaps.length)command.append(el('div','muted',`No observable: ${run.command_gaps.join(', ')}`));body.append(command);
  if(run.report_uri){const report=el('a','', 'Abrir informe de penetraci�n');report.href=run.report_uri;report.rel='noopener';body.append(report)}
  const agents=el('div','grid');run.agents.forEach(agent=>{const box=el('section','box');box.append(el('h3','',`${agent.name}${agent.status?' · '+agent.status:''}`));if(agent.task)box.append(el('p','',agent.task));if(!agent.skills.length)box.append(el('span','muted','Sin skills registradas'));agent.skills.forEach(skill=>{const row=el('div');row.append(badge(`${skill.name}: ${skill.utility==='not_observable'?'No observable':skill.utility}`,skill.utility));if(skill.reason)row.append(el('span','muted',skill.reason));box.append(row)});agents.append(box)});body.append(agents);details.append(body);return details;
}
function render(){const profile=$('profile').value,status=$('status').value,from=$('from').value,to=$('to').value,query=$('search').value.trim().toLowerCase();const filtered=data.runs.filter(run=>{const day=(run.start_time||'').slice(0,10);const haystack=JSON.stringify([run.run_id,run.run_name,run.profile_candidates,run.agents.map(a=>[a.name,a.task,a.skills.map(s=>s.name)])]).toLowerCase();return(!profile||run.profile_candidates.includes(profile))&&(!status||run.status===status)&&(!from||day>=from)&&(!to||day<=to)&&(!query||haystack.includes(query))});const root=$('runs');root.replaceChildren(...filtered.map(renderRun));$('count').textContent=`${filtered.length} ejecuci�n(es)`}
['profile','status','from','to','search'].forEach(id=>$(id).addEventListener('input',render));
$('download').addEventListener('click',()=>{const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='strix-history.json';link.click();URL.revokeObjectURL(link.href)});render();
</script>
</body>
</html>
"""
    return template.replace("__PAYLOAD__", embedded)


def show_history(args: argparse.Namespace) -> int:
    """List historical Strix runs and optionally export JSON or standalone HTML."""
    config = load_config(args.config)
    name = args.name
    run_selector = args.run
    all_runs = args.all
    if name and name.isdecimal():
        if run_selector:
            raise UserError("No combines un ID posicional con --run/--id.")
        run_selector = name
        name = None
        all_runs = True
    elif run_selector and not name:
        all_runs = True
    if all_runs and name:
        raise UserError("No combines una aplicaci�n con --all.")
    if not all_runs and not name:
        raise UserError("Indica una aplicaci�n o utiliza --all.")
    from_date = parse_history_date(args.from_date, "--from") if args.from_date else None
    to_date = parse_history_date(args.to_date, "--to") if args.to_date else None
    if from_date and to_date and from_date > to_date:
        raise UserError("--from no puede ser posterior a --to.")
    profile = None if all_runs else name
    runs = collect_history_runs(
        config,
        profile=profile,
        from_date=from_date,
        to_date=to_date,
        run_selector=run_selector,
    )
    payload = history_payload(
        runs,
        profile=profile,
        from_date=from_date,
        to_date=to_date,
    )
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif args.html is not None:
        destination = args.html.expanduser()
        if not destination.is_absolute():
            destination = Path.cwd() / destination
        atomic_private_text(destination, standalone_history_html(payload))
        print(f"Historial HTML guardado en {destination}")
    else:
        print_history_runs(runs, details=args.details)
    return 0


def resume_state_error(run: HistoryRun) -> str | None:
    """Return why a historical run cannot be resumed, if anything is missing."""
    state_dir = Path(run.run_dir) / ".state"
    agents_path = state_dir / "agents.json"
    if not agents_path.is_file():
        return "falta .state/agents.json"
    agents = read_json_artifact(agents_path, MAX_AGENTS_STATE_BYTES)
    if not isinstance(agents, dict):
        return ".state/agents.json no es un JSON válido"
    if not (state_dir / "agents.db").is_file():
        return "falta .state/agents.db"
    return None


def resumable_history_runs(config: dict[str, Any]) -> list[HistoryRun]:
    """Return resumable runs while preserving the IDs shown by full history."""
    return [
        run
        for run in collect_history_runs(config)
        if resume_state_error(run) is None
    ]


def print_resumable_runs(runs: Sequence[HistoryRun]) -> None:
    """Print the historical runs whose persisted agent state can be restored."""
    if not runs:
        print("No se encontraron ejecuciones reanudables.")
        return
    profile_width = max(
        len("Aplicación"),
        *(len(history_profile_label(run)) for run in runs),
    )
    status_width = max(len("Estado"), *(len(run.status) for run in runs))
    id_width = max(len("ID"), *(len(str(run.selection_id)) for run in runs))
    print(
        f"{'ID':>{id_width + 2}} {'Fecha':<25}  "
        f"{'Aplicación':<{profile_width}}  {'Estado':<{status_width}}  Run"
    )
    print(
        f"{'-' * (id_width + 2)} {'-' * 25}  "
        f"{'-' * profile_width}  {'-' * status_width}  {'-' * 20}"
    )
    for run in runs:
        print(
            f"[{run.selection_id:>{id_width}}] "
            f"{(run.start_time or '-')[:25]:<25}  "
            f"{history_profile_label(run):<{profile_width}}  "
            f"{run.status:<{status_width}}  {Path(run.run_dir).name}"
        )


def resolve_resume_run(config: dict[str, Any], selector: str) -> HistoryRun:
    """Resolve a history ID, Strix run ID, or run directory for resumption."""
    runs = collect_history_runs(config, run_selector=selector)
    if not runs:
        raise UserError(f"No existe una ejecución con el selector {selector!r}.")
    if len(runs) > 1:
        raise UserError(
            f"El selector {selector!r} coincide con varias ejecuciones; utiliza su ID."
        )
    run = runs[0]
    error = resume_state_error(run)
    if error:
        raise UserError(
            f"La ejecución {run.selection_id} ({Path(run.run_dir).name}) "
            f"no se puede reanudar: {error}."
        )
    return run


def resume_run(args: argparse.Namespace) -> int:
    """List resumable sessions or restore one through Strix's native CLI."""
    config = load_config(args.config)
    if args.selector == "list":
        print_resumable_runs(resumable_history_runs(config))
        return 0

    _, path_strix = require_global_paths(config)
    run = resolve_resume_run(config, args.selector)
    run_name = Path(run.run_dir).name
    command = ["uv", "run", "strix"]
    if args.non_interactive:
        command.append("--non-interactive")
    command.extend(["--resume", run_name])
    print(
        f"Reanudando [{run.selection_id}] {run_name} "
        f"({history_profile_label(run)})"
    )
    print(f"cwd={path_strix}")
    print(shlex.join(command))
    if args.dry_run:
        return 0
    try:
        result = subprocess.run(command, cwd=path_strix, check=False)
    except FileNotFoundError as exc:
        raise UserError(f"No se encontró el ejecutable: {exc.filename}") from exc
    if result.returncode != 0:
        print(
            f"Strix terminó con código {result.returncode} al reanudar {run_name}.",
            file=sys.stderr,
        )
    return result.returncode


def save_execution_summary(
    config: dict[str, Any], args: argparse.Namespace, results: Sequence[ExecutionResult]
) -> tuple[Path, Path]:
    directory = log_root(config, getattr(args, "app_log_dir", None)) / args.log_run_id
    json_path = directory / "summary.json"
    markdown_path = directory / "summary.md"
    payload = {
        "runner_version": __version__,
        "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "results": [asdict(result) for result in results],
    }
    atomic_private_text(
        json_path,
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    )
    lines = ["# Resumen de ejecución de Strix", ""]
    for result in results:
        lines.extend(
            [
                f"## {result.profile}",
                "",
                f"- Estado: {result.outcome}",
                f"- Estado Strix: {result.strix_status or 'no identificado'}",
                f"- Código de salida: {result.returncode}",
                f"- Hallazgos: {result.findings}",
                f"- Duración: {format_duration(result.duration_seconds)}",
            ]
        )
        if result.report_path:
            lines.append(f"- Informe: `{result.report_path}`")
        if result.executive_summary:
            lines.extend(["", "### Resumen ejecutivo", "", result.executive_summary])
        lines.append("")
    atomic_private_text(markdown_path, "\n".join(lines).rstrip() + "\n")
    return json_path, markdown_path


def read_instruction_text(path: Path, label: str) -> str:
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise UserError(f"No se pudo leer {label} {path}: {exc}") from exc
    if not text:
        raise UserError(f"{label.capitalize()} está vacío: {path}")
    return text


@contextmanager
def command_with_additional_instruction(
    command: Sequence[str], additional_path: Path | None
) -> Iterator[list[str]]:
    """Temporarily combine the configured and per-run instruction files."""
    combined_command = list(command)
    if additional_path is None:
        yield combined_command
        return

    instruction_indexes = [
        index
        for index, argument in enumerate(combined_command)
        if argument == "--instruction-file"
    ]
    has_inline_instruction = any(
        argument == "--instruction" or argument.startswith("--instruction=")
        for argument in combined_command
    )
    has_inline_instruction_file = any(
        argument.startswith("--instruction-file=")
        for argument in combined_command
    )
    if (
        has_inline_instruction
        or has_inline_instruction_file
        or len(instruction_indexes) > 1
    ):
        raise UserError(
            "No se puede combinar --additional-instruction-file con argumentos "
            "--instruction/--instruction-file añadidos mediante --strix-arg."
        )

    sections: list[str] = []
    instruction_index = instruction_indexes[0] if instruction_indexes else None
    if instruction_index is not None:
        try:
            configured_path = Path(combined_command[instruction_index + 1])
        except IndexError as exc:
            raise UserError("--instruction-file no tiene una ruta asociada.") from exc
        sections.append(
            "# Configured instructions\n\n"
            + read_instruction_text(configured_path, "el archivo de instrucciones")
        )

    resolved_additional = additional_path.expanduser()
    sections.append(
        "# Additional instructions for this run\n\n"
        + read_instruction_text(
            resolved_additional,
            "el archivo de instrucciones adicionales",
        )
    )

    fd, temporary_name = tempfile.mkstemp(
        prefix="strix-runner-instructions-",
        suffix=".md",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n\n".join(sections))
            handle.write("\n")
        os.chmod(temporary_path, 0o600)
        if instruction_index is None:
            combined_command.extend(["--instruction-file", str(temporary_path)])
        else:
            combined_command[instruction_index + 1] = str(temporary_path)
        yield combined_command
    finally:
        temporary_path.unlink(missing_ok=True)


def additional_instruction_path(
    config: dict[str, Any],
    name: str,
    command_line_path: Path | None,
) -> Path | None:
    """Resolve a per-run override or the optional path stored in the profile."""
    if command_line_path is not None:
        return command_line_path.expanduser()
    raw_path = config["applications"][name].get("additional_instruction_file")
    if not raw_path:
        return None
    path_base, _ = require_global_paths(config)
    return resolve_from(path_base, raw_path)


def application_selection_names(applications: dict[str, Any]) -> list[str]:
    """Return the canonical order used by list, run IDs, and the selector."""
    return sorted(applications)


def resolve_application_selectors(
    applications: dict[str, Any], selectors: list[str]
) -> list[str]:
    """Resolve profile names or displayed numeric IDs, preserving selection order."""
    names = application_selection_names(applications)
    selected: list[str] = []
    for selector_group in selectors:
        for selector in selector_group.split(","):
            selector = selector.strip()
            if not selector:
                raise UserError("La lista de aplicaciones contiene un selector vacío.")
            if selector in applications:
                name = selector
            else:
                try:
                    application_id = int(selector)
                except ValueError as exc:
                    raise UserError(
                        f"No existe la aplicación ni el ID {selector!r}."
                    ) from exc
                if application_id < 1 or application_id > len(names):
                    raise UserError(f"ID de aplicación fuera de rango: {application_id}.")
                name = names[application_id - 1]
            if name not in selected:
                selected.append(name)
    return selected


def choose_applications(applications: dict[str, Any]) -> list[str]:
    names = application_selection_names(applications)
    if not names:
        raise UserError("No hay aplicaciones guardadas.")
    if not sys.stdin.isatty():
        raise UserError("Indica aplicaciones en la orden o utiliza --all.")
    print("Aplicaciones disponibles:")
    for index, name in enumerate(names, start=1):
        profile = applications[name]
        code_paths = profile_code_paths(name, profile)
        urls = profile_urls(name, profile)
        code = f"{len(code_paths)} repo(s)" if code_paths else "sin código"
        target = f"{len(urls)} URL(s)" if urls else "solo caja blanca"
        print(f"  {index:>2}. {name} ({code}) - {target}")
    raw = input("Selecciona números separados por coma (o 'all'): ").strip()
    if raw.lower() in {"all", "todas", "*"}:
        return names
    try:
        indexes = [int(item.strip()) for item in raw.split(",") if item.strip()]
    except ValueError as exc:
        raise UserError("La selección debe contener números separados por comas.") from exc
    if not indexes or any(index < 1 or index > len(names) for index in indexes):
        raise UserError("Selección vacía o fuera de rango.")
    return list(dict.fromkeys(names[index - 1] for index in indexes))


def configure(args: argparse.Namespace) -> int:
    config = load_config(args.config, must_exist=False)
    globals_ = config["globals"]
    if args.path_base is not None:
        globals_["path_base"] = str(Path(args.path_base).expanduser())
    if args.path_strix is not None:
        globals_["path_strix"] = str(Path(args.path_strix).expanduser())
    if args.clear_log_dir:
        globals_.pop("log_dir", None)
    elif args.log_dir is not None:
        globals_["log_dir"] = str(Path(args.log_dir).expanduser())
    if not globals_.get("path_base") or not globals_.get("path_strix"):
        raise UserError("Debes indicar --path-base y --path-strix la primera vez.")
    save_config(args.config, config)
    print(f"Configuración guardada en {args.config}")
    return 0


def save_application(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    applications = config["applications"]
    existing = applications.get(args.name)
    profile = dict(existing or {})
    if args.clear_url:
        profile.pop("url", None)
        profile.pop("urls", None)
    elif args.urls is not None:
        for url in args.urls:
            validate_url(url)
        profile.pop("url", None)
        profile.pop("urls", None)
        if len(args.urls) == 1:
            profile["url"] = args.urls[0]
        else:
            profile["urls"] = args.urls
    if args.clear_code:
        profile.pop("code_path", None)
        profile.pop("code_paths", None)
    elif args.code_paths is not None:
        profile.pop("code_path", None)
        profile.pop("code_paths", None)
        if len(args.code_paths) == 1:
            profile["code_path"] = args.code_paths[0]
        else:
            profile["code_paths"] = args.code_paths
    if args.instruction_file is not None:
        profile["instruction_file"] = args.instruction_file
    elif existing is None:
        profile["instruction_file"] = DEFAULT_INSTRUCTION_FILE
    if args.clear_additional_instruction_file:
        profile.pop("additional_instruction_file", None)
    elif args.additional_instruction_file is not None:
        profile["additional_instruction_file"] = args.additional_instruction_file
    if args.workspace_files is not None:
        profile["workspace_files"] = args.workspace_files
    elif existing is None:
        profile["workspace_files"] = DEFAULT_WORKSPACE_FILES.copy()
    if args.scan_mode is not None:
        profile["scan_mode"] = args.scan_mode
    elif existing is None:
        profile["scan_mode"] = DEFAULT_SCAN_MODE
    if args.extra_args is not None:
        profile["extra_args"] = args.extra_args
    if args.clear_start_command:
        profile.pop("start_command", None)
        profile.pop("start_wait_seconds", None)
    elif args.start_command is not None:
        profile["start_command"] = args.start_command
    if args.start_wait_seconds is not None:
        profile["start_wait_seconds"] = args.start_wait_seconds
    if args.stop_grace_seconds is not None:
        profile["stop_grace_seconds"] = args.stop_grace_seconds
    if args.clear_stop_command:
        profile.pop("stop_command", None)
    elif args.stop_command is not None:
        profile["stop_command"] = args.stop_command
    if args.clear_command_cwd:
        profile.pop("command_cwd", None)
    elif args.command_cwd is not None:
        profile["command_cwd"] = args.command_cwd
    validate_profile(args.name, profile)
    applications[args.name] = profile
    save_config(args.config, config)
    print(f"Aplicación {args.name!r} guardada en {args.config}")
    return 0


def list_applications(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.json:
        print(json.dumps(config, ensure_ascii=False, indent=2))
        return 0
    path_base, path_strix = require_global_paths(config)
    print(f"PATH_BASE: {path_base}")
    print(f"PATH_STRIX:   {path_strix}")
    print(f"LOG_DIR:      {log_root(config)}")
    print("Aplicaciones (ID de selección):")
    names = application_selection_names(config["applications"])
    id_width = len(str(len(names)))
    for application_id, name in enumerate(names, start=1):
        profile = config["applications"][name]
        urls = profile_urls(name, profile)
        code_paths = profile_code_paths(name, profile)
        url = ", ".join(urls) if urls else "sin URL"
        code = ", ".join(code_paths) if code_paths else "-"
        start = profile.get("start_command", "—")
        additional = profile.get("additional_instruction_file", "-")
        print(
            f"  [{application_id:>{id_width}}] {name}: {url} | "
            f"código: {code} | instrucciones adicionales: {additional} | "
            f"arranque: {start}"
        )
    if names:
        example_ids = [1]
        if len(names) > 1:
            example_ids.append(min(3, len(names)))
        example_argument = ",".join(str(application_id) for application_id in example_ids)
        example_names = ", ".join(
            f"[{application_id}] {names[application_id - 1]}"
            for application_id in example_ids
        )
        print("\nEjemplo de ejecución por ID:")
        print(f"  strix_runner run {example_argument}")
        print(f"  Selecciona: {example_names}")
    return 0


def remove_application(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.name not in config["applications"]:
        raise UserError(f"No existe la aplicación {args.name!r}.")
    del config["applications"][args.name]
    save_config(args.config, config)
    print(f"Aplicación {args.name!r} eliminada.")
    return 0


def show_version(args: argparse.Namespace) -> int:
    print(f"strix-runner {__version__}")
    return 0


def verify_configuration(args: argparse.Namespace) -> int:
    """Validate the JSON model and, by default, all referenced local paths."""
    config = load_config(args.config)
    path_base, path_strix = require_global_paths(config)
    errors: list[str] = []

    if not args.json_only:
        if not path_base.is_dir():
            errors.append(f"PATH_BASE no es un directorio: {path_base}")
        if not path_strix.is_dir():
            errors.append(f"PATH_STRIX no es un directorio: {path_strix}")
        configured_log_root = log_root(config)
        if configured_log_root.exists() and not configured_log_root.is_dir():
            errors.append(
                f"LOG_DIR existe pero no es un directorio: {configured_log_root}"
            )

    for name in sorted(config["applications"]):
        try:
            command, cwd = build_command(config, name)
            if not args.json_only:
                validate_runtime_paths(config, name, command, cwd)
                project_command(config, name, "start_command")
                project_command(config, name, "stop_command")
        except UserError as exc:
            errors.append(f"{name}: {exc}")

    if errors:
        details = "\n  - ".join(errors)
        raise UserError(f"La configuración no es válida:\n  - {details}")

    mode = "estructura JSON" if args.json_only else "estructura JSON y rutas"
    print(f"Configuración válida ({mode}): {args.config}")
    print(f"Versión del esquema: {config['version']}")
    print(f"Aplicaciones válidas: {len(config['applications'])}")
    return 0


def run_applications(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.all and args.names:
        raise UserError("No combines nombres de aplicaciones con --all.")
    if args.all:
        names = application_selection_names(config["applications"])
    elif args.names:
        names = resolve_application_selectors(config["applications"], args.names)
    else:
        names = choose_applications(config["applications"])
    if not names:
        raise UserError("No hay aplicaciones seleccionadas.")
    args.log_run_id = new_log_run_id()

    final_status = 0
    results: list[ExecutionResult] = []
    summary_mode = getattr(args, "report_summary", "short")
    try:
        for name in names:
            try:
                execution = execute_application_with_report(config, name, args)
            except ApplicationInterrupted as exc:
                execution = exc.result
                results.append(execution)
                print_execution_result(execution, summary_mode)
                final_status = 130
                return final_status
            except (UserError, OSError) as exc:
                execution = ExecutionResult(
                    profile=name,
                    returncode=1,
                    outcome="ERROR",
                    error=str(exc),
                )
                results.append(execution)
                print_execution_result(execution, summary_mode)
                final_status = final_status or 1
                if not args.keep_going:
                    raise
                continue

            results.append(execution)
            print_execution_result(execution, summary_mode)
            if execution.returncode != 0:
                final_status = execution.returncode
            if execution.is_operational_failure and not args.keep_going:
                return final_status
        return final_status
    finally:
        print_final_execution_summary(results)
        if results and not getattr(args, "dry_run", False):
            try:
                json_path, markdown_path = save_execution_summary(config, args, results)
            except (OSError, UserError) as exc:
                print(f"No se pudo guardar el resumen de ejecución: {exc}", file=sys.stderr)
            else:
                print(f"Resumen JSON: {json_path}")
                print(f"Resumen Markdown: {markdown_path}")


def run_application(
    config: dict[str, Any], name: str, args: argparse.Namespace
) -> int:
    """Build, validate and execute one application profile."""
    command, cwd = build_command(
        config,
        name,
        code_mode=args.code_mode,
        target_mode=getattr(args, "target_mode", None),
        non_interactive=args.non_interactive,
    )
    if not args.no_validate:
        validate_runtime_paths(
            config,
            name,
            command,
            cwd,
            ignore_configured_additional=(
                args.additional_instruction_file is not None
            ),
        )
    with command_with_additional_instruction(
        command,
        additional_instruction_path(
            config,
            name,
            args.additional_instruction_file,
        ),
    ) as effective_command:
        skip_project_lifecycle = (
            args.skip_start or getattr(args, "target_mode", None) == "code"
        )
        start_spec = (
            None
            if skip_project_lifecycle
            else project_command(config, name, "start_command")
        )
        stop_spec = (
            None
            if skip_project_lifecycle
            else project_command(config, name, "stop_command")
        )
        args.observed_strix_command = list(effective_command)
        args.observed_strix_cwd = cwd
        args.observed_start_spec = start_spec
        args.observed_stop_spec = stop_spec
        print(f"\n[{name}] cwd={cwd}")
        if start_spec is not None:
            start_command, start_cwd = start_spec
            print(
                f"[{name}] arranque (cwd={start_cwd}): "
                f"{shlex.join(start_command)}"
            )
        print(shlex.join(effective_command))
        if stop_spec is not None:
            stop_command, stop_cwd = stop_spec
            print(
                f"[{name}] parada (cwd={stop_cwd}): {shlex.join(stop_command)}"
            )
        has_lifecycle = start_spec is not None or stop_spec is not None
        app_log_path = None
        if has_lifecycle:
            app_log_path = application_log_path(
                config,
                name,
                getattr(args, "log_run_id", new_log_run_id()),
                args.app_log_dir,
            )
            print(f"[{name}] log de aplicación: {app_log_path}")
        if args.dry_run:
            return 0

        managed_process: ManagedProcess | None = None
        stop_grace_seconds = float(
            config["applications"][name].get("stop_grace_seconds", 10.0)
        )
        log_context = (
            application_log(app_log_path, name)
            if app_log_path is not None
            else nullcontext(None)
        )
        with log_context as app_output:
            try:
                if start_spec is not None:
                    start_command, start_cwd = start_spec
                    write_log_event(app_output, "START", start_command, start_cwd)
                    managed_process = start_managed_process(
                        start_command,
                        start_cwd,
                        app_output,
                    )
                    wait_for_startup(
                        managed_process.process,
                        float(
                            config["applications"][name].get(
                                "start_wait_seconds", 5.0
                            )
                        ),
                        name,
                    )
                result = subprocess.run(effective_command, cwd=cwd, check=False)
            except FileNotFoundError as exc:
                raise UserError(
                    f"No se encontró el ejecutable: {exc.filename}"
                ) from exc
            finally:
                stop_project(
                    managed_process,
                    stop_spec,
                    name,
                    app_output,
                    stop_grace_seconds,
                )
        if result.returncode != 0:
            print(
                f"[{name}] Strix terminó con código {result.returncode}.",
                file=sys.stderr,
            )
        return result.returncode


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Guarda perfiles y ejecuta pentests autorizados con Strix.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help=f"JSON de configuración (por defecto: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"strix-runner {__version__}",
        help="Muestra la versión del script y termina",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    version_parser = subparsers.add_parser(
        "version", help="Muestra la versión del script"
    )
    version_parser.set_defaults(handler=show_version)

    verify_parser = subparsers.add_parser(
        "verify", help="Comprueba el JSON de configuración y sus rutas"
    )
    verify_parser.add_argument(
        "--json-only",
        action="store_true",
        help="Comprueba la estructura y los perfiles sin acceder a las rutas",
    )
    verify_parser.set_defaults(handler=verify_configuration)

    config_parser = subparsers.add_parser("configure", help="Configura rutas globales")
    config_parser.add_argument("--path-base", help="Ruta base de archivos y código")
    config_parser.add_argument(
        "--path-strix", help="Directorio desde el que ejecutar 'uv run strix'"
    )
    log_dir_group = config_parser.add_mutually_exclusive_group()
    log_dir_group.add_argument(
        "--log-dir",
        help=(
            "Directorio global para logs; si es relativo se resuelve respecto "
            "a PATH_BASE"
        ),
    )
    log_dir_group.add_argument(
        "--clear-log-dir",
        action="store_true",
        help="Restaura el directorio de logs predeterminado",
    )
    config_parser.set_defaults(handler=configure)

    save_parser = subparsers.add_parser(
        "save",
        help="Crea o actualiza una aplicación",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Ejemplo:
  python3 strix_runner.py save aplicacion-local \\
    --url http://localhost:3000 \\
    --url http://localhost:8080/api \\
    --code-path github/frontend \\
    --code-path github/backend \\
    --command-cwd github \\
    --instruction-file instructions/base.md \\
    --additional-instruction-file instructions/puntual.md \\
    --scan-mode standard \\
    --start-command "docker compose up" \\
    --stop-command "docker compose down" \\
    --start-wait-seconds 30 \\
    --stop-grace-seconds 10

Las rutas relativas se resuelven respecto a PATH_BASE.
""",
    )
    save_parser.add_argument("name", help="Nombre único del perfil")
    url_group = save_parser.add_mutually_exclusive_group()
    url_group.add_argument(
        "-u",
        "--url",
        dest="urls",
        action="append",
        help="URL objetivo; repetible. Al usarla sustituye las URL guardadas.",
    )
    url_group.add_argument(
        "--clear-url", action="store_true", help="Quita la URL guardada (caja blanca)"
    )
    code_group = save_parser.add_mutually_exclusive_group()
    code_group.add_argument(
        "-c",
        "--code-path",
        dest="code_paths",
        action="append",
        help=(
            "Código local, absoluto o relativo a PATH_BASE; repetible. "
            "Al usarlo sustituye las rutas guardadas."
        ),
    )
    code_group.add_argument("--clear-code", action="store_true", help="Quita el código guardado")
    save_parser.add_argument(
        "-i", "--instruction-file", help="Ruta absoluta o relativa a PATH_BASE"
    )
    additional_instruction_group = save_parser.add_mutually_exclusive_group()
    additional_instruction_group.add_argument(
        "--additional-instruction-file",
        help=(
            "Archivo opcional de instrucciones adicionales; absoluto o relativo "
            "a PATH_BASE"
        ),
    )
    additional_instruction_group.add_argument(
        "--clear-additional-instruction-file",
        action="store_true",
        help="Quita el archivo adicional guardado",
    )
    save_parser.add_argument(
        "-w",
        "--workspace-file",
        dest="workspace_files",
        action="append",
        help="Archivo de workspace; repetible. Al usarlo sustituye la lista guardada.",
    )
    save_parser.add_argument(
        "--scan-mode", choices=("quick", "standard", "deep"), help="Modo de escaneo"
    )
    save_parser.add_argument(
        "--strix-arg",
        dest="extra_args",
        action="append",
        help="Argumento Strix adicional; repetible (p. ej. --strix-arg=--max-budget=20)",
    )
    start_group = save_parser.add_mutually_exclusive_group()
    start_group.add_argument(
        "--start-command",
        help="Comando para levantar el proyecto desde code_path",
    )
    start_group.add_argument(
        "--clear-start-command",
        action="store_true",
        help="Quita el comando de arranque guardado",
    )
    save_parser.add_argument(
        "--start-wait-seconds",
        type=float,
        help="Espera tras arrancar antes de lanzar Strix (por defecto: 5)",
    )
    stop_group = save_parser.add_mutually_exclusive_group()
    stop_group.add_argument(
        "--stop-command",
        help="Comando opcional de parada ejecutado después de Strix",
    )
    stop_group.add_argument(
        "--clear-stop-command",
        action="store_true",
        help="Quita el comando de parada guardado",
    )
    save_parser.add_argument(
        "--stop-grace-seconds",
        type=float,
        help=(
            "Espera para finalizar el grupo antes de forzar SIGKILL "
            "(por defecto: 10)"
        ),
    )
    command_cwd_group = save_parser.add_mutually_exclusive_group()
    command_cwd_group.add_argument(
        "--command-cwd",
        help=(
            "Directorio para los comandos de arranque/parada; obligatorio si "
            "hay varios code_path"
        ),
    )
    command_cwd_group.add_argument(
        "--clear-command-cwd",
        action="store_true",
        help="Quita el directorio de comandos guardado",
    )
    save_parser.set_defaults(handler=save_application)

    list_parser = subparsers.add_parser("list", help="Lista configuración y aplicaciones")
    list_parser.add_argument("--json", action="store_true", help="Muestra el JSON completo")
    list_parser.set_defaults(handler=list_applications)

    history_parser = subparsers.add_parser(
        "history",
        help="Consulta y exporta las ejecuciones guardadas por Strix",
    )
    history_parser.add_argument(
        "name",
        nargs="?",
        help="Aplicación o ID mostrado en el historial completo",
    )
    history_parser.add_argument(
        "--all",
        action="store_true",
        help="Incluye todas las ejecuciones, también las no asociadas",
    )
    history_parser.add_argument(
        "--from",
        dest="from_date",
        metavar="AAAA-MM-DD",
        help="Fecha inicial inclusiva",
    )
    history_parser.add_argument(
        "--to",
        dest="to_date",
        metavar="AAAA-MM-DD",
        help="Fecha final inclusiva",
    )
    history_parser.add_argument(
        "--run",
        "--id",
        dest="run",
        help="ID mostrado, run_id o nombre de ejecución",
    )
    history_parser.add_argument(
        "--details",
        action="store_true",
        help="Muestra comandos, agentes, skills y utilidad observable",
    )
    history_output_group = history_parser.add_mutually_exclusive_group()
    history_output_group.add_argument(
        "--json",
        action="store_true",
        help="Emite el modelo normalizado como JSON",
    )
    history_output_group.add_argument(
        "--html",
        type=Path,
        metavar="ARCHIVO",
        help="Genera un informe HTML standalone con permisos privados",
    )
    history_parser.set_defaults(handler=show_history)

    resume_parser = subparsers.add_parser(
        "resume",
        help="Lista o reanuda una sesión guardada de Strix",
    )
    resume_parser.add_argument(
        "selector",
        help="'list', ID del historial, run_id o nombre del directorio de ejecución",
    )
    resume_parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help="Reanuda sin interfaz interactiva",
    )
    resume_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Muestra el comando sin ejecutar Strix",
    )
    resume_parser.set_defaults(handler=resume_run)

    remove_parser = subparsers.add_parser("remove", help="Elimina una aplicación")
    remove_parser.add_argument("name")
    remove_parser.set_defaults(handler=remove_application)

    run_parser = subparsers.add_parser("run", help="Ejecuta una o varias aplicaciones")
    run_parser.add_argument(
        "names",
        nargs="*",
        help=(
            "Nombres o ID mostrados por 'list'; admite varios y listas separadas "
            "por comas. Si se omiten, muestra selector"
        ),
    )
    run_parser.add_argument("--all", action="store_true", help="Ejecuta todos los perfiles")
    target_mode_group = run_parser.add_mutually_exclusive_group()
    target_mode_group.add_argument(
        "--only-code",
        dest="target_mode",
        action="store_const",
        const="code",
        help="Analiza solo los repositorios de código y no levanta la aplicación",
    )
    target_mode_group.add_argument(
        "--only-pentesting",
        dest="target_mode",
        action="store_const",
        const="pentesting",
        help="Ejecuta pentesting solo contra las URL configuradas",
    )
    target_mode_group.add_argument(
        "--code-mode",
        choices=("auto", "include", "exclude"),
        default="auto",
        help=(
            "Compatibilidad: auto incluye todo, include exige código y exclude "
            "equivale a --only-pentesting"
        ),
    )
    run_parser.add_argument(
        "-n", "--non-interactive", action="store_true", help="Pasa --non-interactive a Strix"
    )
    run_parser.add_argument("--dry-run", action="store_true", help="Imprime sin ejecutar")
    run_parser.add_argument(
        "--app-log-dir",
        type=Path,
        help=(
            "Sobrescribe el directorio de logs para esta ejecución; las rutas "
            "relativas parten del directorio actual"
        ),
    )
    run_parser.add_argument(
        "--additional-instruction-file",
        type=Path,
        help=(
            "Sobrescribe durante esta ejecución el archivo adicional guardado; "
            "la ruta se interpreta desde el directorio actual"
        ),
    )
    run_parser.add_argument(
        "--no-validate", action="store_true", help="No comprueba directorios/archivos locales"
    )
    run_parser.add_argument(
        "--keep-going", action="store_true", help="Continúa si falla una aplicación"
    )
    run_parser.add_argument(
        "--report-summary",
        choices=("short", "full", "none"),
        default="short",
        help=(
            "Resumen ejecutivo tras cada prueba: short lo limita, full lo "
            "muestra completo y none lo oculta (por defecto: short)"
        ),
    )
    run_parser.add_argument(
        "--skip-start",
        action="store_true",
        help="No ejecuta los comandos de arranque/parada guardados",
    )
    run_parser.set_defaults(handler=run_applications)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    args.config = args.config.expanduser()
    try:
        return args.handler(args)
    except UserError as exc:
        parser.error(str(exc))
    except OSError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
