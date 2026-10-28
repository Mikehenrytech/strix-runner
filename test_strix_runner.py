import json
import io
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import strix_runner


class StrixRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.strix = self.base / "strix"
        self.strix.mkdir()
        self.config = {
            "version": 1,
            "globals": {
                "path_base": str(self.base),
                "path_strix": str(self.strix),
                "log_dir": str(self.base / "runner-logs"),
            },
            "applications": {
                "app": {
                    "url": "https://example.test/app",
                    "code_path": "source code/app",
                    "instruction_file": "instructions/a file.md",
                    "workspace_files": ["token.json", "mail otp.py"],
                    "scan_mode": "deep",
                }
            },
        }

    def write_strix_run(
        self,
        run_name="example-run",
        *,
        status="completed",
        targets=None,
        findings=None,
        executive_summary="Assessment completed successfully.",
        models=None,
    ):
        run_dir = self.strix / "strix_runs" / run_name
        run_dir.mkdir(parents=True)
        record = {
            "run_name": run_name,
            "status": status,
            "start_time": "2026-10-05T10:00:00+00:00",
            "end_time": "2026-10-05T10:02:30+00:00",
            "targets_info": [
                {"original": target}
                for target in (targets or ["https://example.test/app"])
            ],
        }
        if models:
            record["llm_usage"] = {
                "agents": [
                    {"agent_name": f"agent-{i}", "model": model}
                    for i, model in enumerate(models)
                ]
            }
        if executive_summary is not None:
            record["scan_results"] = {
                "executive_summary": executive_summary,
                "methodology": "Method",
                "technical_analysis": "Analysis",
                "recommendations": "Recommendations",
            }
            (run_dir / "penetration_test_report.md").write_text(
                "# Report\n", encoding="utf-8"
            )
        (run_dir / "run.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        (run_dir / "vulnerabilities.json").write_text(
            json.dumps(findings or []), encoding="utf-8"
        )
        return run_dir, record

    def write_resume_state(self, run_dir, *, agents=None):
        state_dir = run_dir / ".state"
        state_dir.mkdir(exist_ok=True)
        (state_dir / "agents.json").write_text(
            json.dumps(agents or {"statuses": {"root": "running"}}),
            encoding="utf-8",
        )
        (state_dir / "agents.db").write_bytes(b"saved SDK session")

    def tearDown(self):
        self.temp.cleanup()

    def test_build_command_includes_url_and_code_as_targets(self):
        command, cwd = strix_runner.build_command(self.config, "app")
        self.assertEqual(cwd, self.strix)
        self.assertEqual(command[:5], ["uv", "run", "strix", "--target", "https://example.test/app"])
        self.assertIn(str(self.base / "source code/app"), command)
        self.assertEqual(command[-2:], ["--scan-mode", "deep"])

    def test_build_command_supports_multiple_urls_and_code_paths(self):
        profile = self.config["applications"]["app"]
        profile.pop("url")
        profile.pop("code_path")
        profile["urls"] = [
            "https://frontend.example.test",
            "https://api.example.test",
        ]
        profile["code_paths"] = ["frontend", "backend"]
        command, _ = strix_runner.build_command(self.config, "app")
        targets = [
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "--target"
        ]
        self.assertEqual(
            targets,
            [
                "https://frontend.example.test",
                "https://api.example.test",
                str(self.base / "frontend"),
                str(self.base / "backend"),
            ],
        )

    def test_only_code_uses_all_repositories_and_no_urls(self):
        profile = self.config["applications"]["app"]
        profile.pop("code_path")
        profile["code_paths"] = ["frontend", "backend"]
        command, _ = strix_runner.build_command(
            self.config,
            "app",
            target_mode="code",
        )
        targets = [
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "--target"
        ]
        self.assertEqual(
            targets,
            [str(self.base / "frontend"), str(self.base / "backend")],
        )

    def test_only_pentesting_uses_all_urls_and_no_repositories(self):
        profile = self.config["applications"]["app"]
        profile.pop("url")
        profile["urls"] = [
            "https://frontend.example.test",
            "https://api.example.test",
        ]
        command, _ = strix_runner.build_command(
            self.config,
            "app",
            target_mode="pentesting",
        )
        targets = [
            command[index + 1]
            for index, argument in enumerate(command)
            if argument == "--target"
        ]
        self.assertEqual(
            targets,
            ["https://frontend.example.test", "https://api.example.test"],
        )

    def test_only_code_requires_repository(self):
        self.config["applications"]["app"].pop("code_path")
        with self.assertRaisesRegex(strix_runner.UserError, "rutas de código"):
            strix_runner.build_command(self.config, "app", target_mode="code")

    def test_only_pentesting_requires_url(self):
        self.config["applications"]["app"].pop("url")
        with self.assertRaisesRegex(strix_runner.UserError, "no tiene URL"):
            strix_runner.build_command(
                self.config,
                "app",
                target_mode="pentesting",
            )

    def test_profile_rejects_singular_and_plural_urls_together(self):
        profile = self.config["applications"]["app"]
        profile["urls"] = ["https://second.example.test"]
        with self.assertRaisesRegex(strix_runner.UserError, "simultáneamente"):
            strix_runner.validate_profile("app", profile)

    def test_exclude_code(self):
        command, _ = strix_runner.build_command(
            self.config, "app", code_mode="exclude"
        )
        self.assertNotIn(str(self.base / "source code/app"), command)

    def test_include_requires_code(self):
        del self.config["applications"]["app"]["code_path"]
        with self.assertRaises(strix_runner.UserError):
            strix_runner.build_command(self.config, "app", code_mode="include")

    def test_config_round_trip(self):
        path = self.base / "nested" / "config.json"
        strix_runner.save_config(path, self.config)
        self.assertEqual(strix_runner.load_config(path), self.config)
        self.assertEqual(json.loads(path.read_text()), self.config)

    def test_example_config_matches_current_schema(self):
        example = Path(__file__).with_name("strix-config.example.json")
        config = strix_runner.load_config(example)
        self.assertEqual(config["version"], 1)
        self.assertEqual(
            set(config["applications"]),
            {"aplicacion-remota", "biblioteca-whitebox", "aplicacion-local"},
        )
        local = config["applications"]["aplicacion-local"]
        self.assertEqual(local["start_command"], "docker compose up")
        self.assertEqual(local["stop_command"], "docker compose down")
        self.assertEqual(local["extra_args"], ["--max-budget", "20"])
        self.assertEqual(
            config["applications"]["aplicacion-remota"][
                "additional_instruction_file"
            ],
            "Instrucciones/skill-audit.md",
        )

    def test_invalid_url(self):
        self.config["applications"]["app"]["url"] = "not-a-url"
        with self.assertRaises(strix_runner.UserError):
            strix_runner.build_command(self.config, "app")

    def test_white_box_profile_does_not_require_url(self):
        del self.config["applications"]["app"]["url"]
        command, _ = strix_runner.build_command(self.config, "app")
        self.assertEqual(command[:3], ["uv", "run", "strix"])
        self.assertEqual(command[3:5], ["--target", str(self.base / "source code/app")])

    def test_profile_requires_at_least_one_target(self):
        del self.config["applications"]["app"]["url"]
        del self.config["applications"]["app"]["code_path"]
        with self.assertRaisesRegex(strix_runner.UserError, "al menos una URL"):
            strix_runner.build_command(self.config, "app")

    def test_cannot_exclude_only_white_box_target(self):
        del self.config["applications"]["app"]["url"]
        with self.assertRaisesRegex(strix_runner.UserError, "no tiene URL"):
            strix_runner.build_command(self.config, "app", code_mode="exclude")

    def test_validation_checks_included_code_path(self):
        for relative in ("instructions/a file.md", "token.json", "mail otp.py"):
            path = self.base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        command, cwd = strix_runner.build_command(self.config, "app")
        with self.assertRaisesRegex(strix_runner.UserError, "ruta de código"):
            strix_runner.validate_runtime_paths(self.config, "app", command, cwd)

    def test_validation_ignores_excluded_code_path(self):
        for relative in ("instructions/a file.md", "token.json", "mail otp.py"):
            path = self.base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        command, cwd = strix_runner.build_command(
            self.config, "app", code_mode="exclude"
        )
        strix_runner.validate_runtime_paths(self.config, "app", command, cwd)

    def test_project_start_command_uses_code_directory(self):
        code_path = self.base / "source code/app"
        code_path.mkdir(parents=True)
        self.config["applications"]["app"]["start_command"] = (
            "uv run python -m demo"
        )
        spec = strix_runner.project_command(self.config, "app", "start_command")
        self.assertEqual(
            spec,
            (["uv", "run", "python", "-m", "demo"], code_path),
        )

    def test_start_command_requires_code_path(self):
        profile = self.config["applications"]["app"]
        del profile["code_path"]
        profile["start_command"] = "npm run dev"
        with self.assertRaisesRegex(strix_runner.UserError, "ruta de código"):
            strix_runner.validate_profile("app", profile)

    def test_stop_command_requires_code_path(self):
        profile = self.config["applications"]["app"]
        del profile["code_path"]
        profile["stop_command"] = "docker compose down"
        with self.assertRaisesRegex(strix_runner.UserError, "ruta de código"):
            strix_runner.validate_profile("app", profile)

    def test_stop_grace_seconds_must_not_be_negative(self):
        profile = self.config["applications"]["app"]
        profile["stop_grace_seconds"] = -1
        with self.assertRaisesRegex(strix_runner.UserError, "stop_grace_seconds"):
            strix_runner.validate_profile("app", profile)

    def test_multiple_code_paths_with_commands_require_command_cwd(self):
        profile = self.config["applications"]["app"]
        profile.pop("code_path")
        profile["code_paths"] = ["frontend", "backend"]
        profile["start_command"] = "docker compose up"
        with self.assertRaisesRegex(strix_runner.UserError, "command_cwd"):
            strix_runner.validate_profile("app", profile)

    def test_project_command_uses_explicit_command_cwd(self):
        profile = self.config["applications"]["app"]
        profile.pop("code_path")
        profile["code_paths"] = ["frontend", "backend"]
        profile["command_cwd"] = "orchestration"
        profile["start_command"] = "docker compose up"
        command_cwd = self.base / "orchestration"
        command_cwd.mkdir()
        spec = strix_runner.project_command(self.config, "app", "start_command")
        self.assertEqual(spec, (["docker", "compose", "up"], command_cwd))

    def test_load_config_rejects_invalid_profile_cleanly(self):
        path = self.base / "config.json"
        self.config["applications"]["app"] = "not-an-object"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        with self.assertRaisesRegex(strix_runner.UserError, "objeto JSON"):
            strix_runner.load_config(path)

    def test_load_config_rejects_non_string_global_path(self):
        path = self.base / "config.json"
        self.config["globals"]["path_strix"] = 42
        path.write_text(json.dumps(self.config), encoding="utf-8")
        with self.assertRaisesRegex(strix_runner.UserError, "path_strix"):
            strix_runner.load_config(path)

    @mock.patch("strix_runner.terminate_process_tree")
    @mock.patch("strix_runner.subprocess.run", side_effect=FileNotFoundError("missing"))
    def test_stop_failure_still_terminates_started_process(self, run, terminate):
        process = mock.Mock()
        managed = strix_runner.ManagedProcess(process, 123)
        strix_runner.stop_project(
            managed,
            (["missing-stop"], self.base),
            "app",
        )
        terminate.assert_called_once_with(managed, "app", 10.0, None)

    @mock.patch("strix_runner.terminate_process_tree")
    @mock.patch("strix_runner.subprocess.run")
    def test_stop_command_disconnects_stdin_and_has_timeout(self, run, terminate):
        run.return_value.returncode = 0
        strix_runner.stop_project(
            None,
            (["docker", "compose", "down"], self.base),
            "app",
            grace_seconds=3,
        )

        run.assert_called_once_with(
            ["docker", "compose", "down"],
            cwd=self.base,
            check=False,
            stdin=strix_runner.subprocess.DEVNULL,
            timeout=3,
        )
        terminate.assert_called_once_with(None, "app", 3, None)

    @mock.patch("strix_runner.terminate_process_tree")
    @mock.patch(
        "strix_runner.subprocess.run",
        side_effect=strix_runner.subprocess.TimeoutExpired(["slow-stop"], 2),
    )
    def test_stop_timeout_still_terminates_started_process(self, run, terminate):
        process = mock.Mock(pid=123)
        managed = strix_runner.ManagedProcess(process, 123)

        strix_runner.stop_project(
            managed,
            (["slow-stop"], self.base),
            "app",
            grace_seconds=2,
        )

        terminate.assert_called_once_with(managed, "app", 2, None)

    def test_application_log_is_private_and_accepts_binary_output(self):
        path = self.base / "logs" / "run" / "app" / "application.log"
        with strix_runner.application_log(path, "app") as output:
            output.write(b"raw:\xff\n")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertIn(b"profile: app", path.read_bytes())
        self.assertIn(b"raw:\xff", path.read_bytes())

    def test_application_log_path_sanitizes_profile_name(self):
        path = strix_runner.application_log_path(
            self.config,
            "../unsafe profile",
            "run-id",
            self.base / "logs",
        )
        self.assertEqual(path.name, "application.log")
        self.assertEqual(path.parents[2], self.base / "logs")
        self.assertNotIn("..", path.parent.name)
        self.assertNotIn(" ", path.parent.name)

    def test_locate_changed_strix_run_matches_all_targets(self):
        before = strix_runner.snapshot_strix_runs(self.strix)
        expected = [
            "https://example.test/app",
            str(self.base / "source code/app"),
        ]
        run_dir, expected_record = self.write_strix_run(targets=expected)

        located, record, error = strix_runner.locate_changed_strix_run(
            self.strix,
            before,
            expected,
        )

        self.assertEqual(located, run_dir.resolve())
        self.assertEqual(record, expected_record)
        self.assertIsNone(error)

    def test_locate_changed_strix_run_rejects_unrelated_artifact(self):
        before = strix_runner.snapshot_strix_runs(self.strix)
        self.write_strix_run(targets=["https://other.example.test"])

        located, record, error = strix_runner.locate_changed_strix_run(
            self.strix,
            before,
            ["https://example.test/app"],
        )

        self.assertIsNone(located)
        self.assertIsNone(record)
        self.assertIn("no coinciden", error)

    def test_build_execution_result_reads_report_and_severity_counts(self):
        findings = [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "medium"},
        ]
        run_dir, record = self.write_strix_run(
            findings=findings,
            executive_summary="Completed\x1b[31m safely\x1b[0m.",
        )

        result = strix_runner.build_execution_result(
            "app", 0, run_dir, record, None, 1.0
        )

        self.assertEqual(result.outcome, "COMPLETADA CON HALLAZGOS")
        self.assertEqual(result.findings, 3)
        self.assertEqual(result.severity_counts["high"], 1)
        self.assertEqual(result.severity_counts["medium"], 2)
        self.assertEqual(result.duration_seconds, 150)
        self.assertEqual(result.executive_summary, "Completed safely.")
        self.assertEqual(result.report_path, str(run_dir / "penetration_test_report.md"))

    def test_build_execution_result_marks_missing_final_report_incomplete(self):
        run_dir, record = self.write_strix_run(
            status="interrupted",
            executive_summary=None,
        )

        result = strix_runner.build_execution_result(
            "app", 0, run_dir, record, None, 10.0
        )

        self.assertEqual(result.outcome, "INCOMPLETA")
        self.assertEqual(result.strix_status, "interrupted")
        self.assertIsNone(result.report_path)
        self.assertIn("sin generar", result.error)

    @mock.patch("strix_runner.run_application")
    def test_execute_application_correlates_artifacts(self, run_application):
        expected_targets = [
            "https://example.test/app",
            str(self.base / "source code/app"),
        ]

        def create_artifacts(_config, _name, _args):
            self.write_strix_run(targets=expected_targets)
            return 0

        run_application.side_effect = create_artifacts
        args = SimpleNamespace(
            code_mode="auto",
            target_mode=None,
            non_interactive=False,
            dry_run=False,
        )

        result = strix_runner.execute_application_with_report(
            self.config, "app", args
        )

        self.assertEqual(result.outcome, "COMPLETADA")
        self.assertEqual(result.run_name, "example-run")
        self.assertEqual(result.returncode, 0)
        runner_record = json.loads(
            (self.strix / "strix_runs/example-run/strix-runner.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(runner_record["profile"], "app")
        self.assertEqual(runner_record["commands"]["strix"]["argv"][:3], ["uv", "run", "strix"])

    @mock.patch("strix_runner.run_application")
    def test_execute_application_preserves_partial_report_on_interrupt(
        self, run_application
    ):
        expected_targets = [
            "https://example.test/app",
            str(self.base / "source code/app"),
        ]

        def interrupt_after_artifacts(_config, _name, _args):
            self.write_strix_run(
                status="interrupted",
                targets=expected_targets,
                executive_summary=None,
            )
            raise KeyboardInterrupt

        run_application.side_effect = interrupt_after_artifacts
        args = SimpleNamespace(
            code_mode="auto",
            target_mode=None,
            non_interactive=False,
            dry_run=False,
        )

        with self.assertRaises(strix_runner.ApplicationInterrupted) as raised:
            strix_runner.execute_application_with_report(self.config, "app", args)

        self.assertEqual(raised.exception.result.outcome, "INCOMPLETA")
        self.assertEqual(raised.exception.result.strix_status, "interrupted")
        self.assertEqual(raised.exception.result.returncode, 130)

    def test_execution_result_completed_exit_two_is_not_operational_failure(self):
        result = strix_runner.ExecutionResult(
            profile="app",
            returncode=2,
            outcome="COMPLETADA CON HALLAZGOS",
            strix_status="completed",
            findings=1,
        )
        self.assertFalse(result.is_operational_failure)

    def test_save_execution_summary_writes_private_json_and_markdown(self):
        args = SimpleNamespace(
            app_log_dir=self.base / "summaries",
            log_run_id="run-id",
        )
        result = strix_runner.ExecutionResult(
            profile="app",
            returncode=0,
            outcome="COMPLETADA",
            strix_status="completed",
            executive_summary="Everything completed.",
        )

        json_path, markdown_path = strix_runner.save_execution_summary(
            self.config, args, [result]
        )

        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["results"][0]["profile"], "app")
        self.assertIn("Everything completed.", markdown_path.read_text(encoding="utf-8"))
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(json_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(markdown_path.stat().st_mode), 0o600)

    @mock.patch("strix_runner.terminate_process_tree")
    @mock.patch("strix_runner.wait_for_startup")
    @mock.patch("strix_runner.os.getpgid", return_value=123)
    @mock.patch("strix_runner.subprocess.Popen")
    @mock.patch("strix_runner.subprocess.run")
    def test_run_redirects_application_and_stop_output_to_log(
        self,
        run,
        popen,
        getpgid,
        wait_for_startup,
        terminate,
    ):
        code_path = self.base / "source code/app"
        code_path.mkdir(parents=True)
        profile = self.config["applications"]["app"]
        profile["start_command"] = "python -m demo"
        profile["stop_command"] = "python -m demo_stop"
        profile["start_wait_seconds"] = 0
        process = mock.Mock(pid=123)
        popen.return_value = process
        run.side_effect = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=0)]
        log_root = self.base / "logs"
        args = SimpleNamespace(
            code_mode="auto",
            non_interactive=False,
            no_validate=True,
            additional_instruction_file=None,
            skip_start=False,
            dry_run=False,
            app_log_dir=log_root,
            log_run_id="run-id",
        )

        status = strix_runner.run_application(self.config, "app", args)

        self.assertEqual(status, 0)
        log_path = log_root / "run-id" / "app" / "application.log"
        self.assertTrue(log_path.is_file())
        log_text = log_path.read_text(encoding="utf-8")
        self.assertIn("START", log_text)
        self.assertIn("python -m demo", log_text)
        self.assertIn("STOP", log_text)
        self.assertIn("python -m demo_stop", log_text)
        start_output = popen.call_args.kwargs["stdout"]
        self.assertIs(popen.call_args.kwargs["stdin"], strix_runner.subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs["stderr"], strix_runner.subprocess.STDOUT)
        self.assertIs(run.call_args_list[1].kwargs["stdout"], start_output)
        self.assertIs(
            run.call_args_list[1].kwargs["stderr"],
            strix_runner.subprocess.STDOUT,
        )
        self.assertNotIn("stdout", run.call_args_list[0].kwargs)
        self.assertTrue(start_output.closed)
        wait_for_startup.assert_called_once()
        terminate.assert_called_once_with(
            strix_runner.ManagedProcess(process, 123),
            "app",
            10.0,
            start_output,
        )

    def test_dry_run_does_not_create_application_log(self):
        code_path = self.base / "source code/app"
        code_path.mkdir(parents=True)
        self.config["applications"]["app"]["start_command"] = "python -m demo"
        log_root = self.base / "logs"
        args = SimpleNamespace(
            code_mode="auto",
            non_interactive=False,
            no_validate=True,
            additional_instruction_file=None,
            skip_start=False,
            dry_run=True,
            app_log_dir=log_root,
            log_run_id="run-id",
        )
        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.run_application(self.config, "app", args)
        self.assertEqual(status, 0)
        self.assertIn("application.log", output.getvalue())
        self.assertFalse(log_root.exists())

    def test_save_help_includes_complete_configuration_example(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            strix_runner.make_parser().parse_args(["save", "--help"])

        self.assertEqual(raised.exception.code, 0)
        help_text = output.getvalue()
        self.assertIn("Ejemplo:", help_text)
        self.assertIn("save aplicacion-local", help_text)
        self.assertEqual(help_text.count("--url http://localhost:"), 2)
        self.assertIn("--code-path github/frontend", help_text)
        self.assertIn("--code-path github/backend", help_text)
        self.assertIn("--additional-instruction-file", help_text)
        self.assertIn('--start-command "docker compose up"', help_text)
        self.assertIn('--stop-command "docker compose down"', help_text)
        self.assertIn("--stop-grace-seconds 10", help_text)
        self.assertIn("PATH_BASE", help_text)

    @mock.patch("strix_runner.run_application")
    def test_keep_going_continues_after_profile_error(self, run_application):
        self.config["applications"]["second"] = {
            "url": "https://second.example.test"
        }
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        run_application.side_effect = [strix_runner.UserError("bad app"), 0]
        args = SimpleNamespace(
            config=config_path,
            all=False,
            names=["app", "second"],
            keep_going=True,
        )
        status = strix_runner.run_applications(args)
        self.assertEqual(status, 1)
        self.assertEqual(run_application.call_count, 2)

    @mock.patch("strix_runner.new_log_run_id", return_value="batch-run")
    @mock.patch("strix_runner.execute_application_with_report")
    def test_completed_findings_do_not_prevent_remaining_profiles(
        self, execute_application, _new_log_run_id
    ):
        self.config["applications"]["second"] = {
            "url": "https://second.example.test"
        }
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        execute_application.side_effect = [
            strix_runner.ExecutionResult(
                profile="app",
                returncode=2,
                outcome="COMPLETADA CON HALLAZGOS",
                strix_status="completed",
                findings=1,
            ),
            strix_runner.ExecutionResult(
                profile="second",
                returncode=0,
                outcome="COMPLETADA",
                strix_status="completed",
            ),
        ]
        summary_root = self.base / "batch-logs"
        args = SimpleNamespace(
            config=config_path,
            all=False,
            names=["app", "second"],
            keep_going=False,
            dry_run=False,
            app_log_dir=summary_root,
            report_summary="none",
        )

        with redirect_stdout(io.StringIO()):
            status = strix_runner.run_applications(args)

        self.assertEqual(status, 2)
        self.assertEqual(execute_application.call_count, 2)
        payload = json.loads(
            (summary_root / "batch-run" / "summary.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(payload["results"]), 2)
        self.assertEqual(payload["results"][0]["findings"], 1)

    @mock.patch("strix_runner.run_application")
    def test_without_keep_going_reraises_profile_error(self, run_application):
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        run_application.side_effect = strix_runner.UserError("bad app")
        args = SimpleNamespace(
            config=config_path,
            all=False,
            names=["app"],
            keep_going=False,
        )
        with self.assertRaisesRegex(strix_runner.UserError, "bad app"):
            strix_runner.run_applications(args)

    @mock.patch("strix_runner.subprocess.run")
    def test_windows_process_tree_uses_taskkill(self, run):
        run.return_value.returncode = 0
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        managed = strix_runner.ManagedProcess(process, None)
        with mock.patch("strix_runner.os.name", "nt"):
            strix_runner.terminate_process_tree(managed, "app")
        run.assert_called_once_with(
            ["taskkill", "/PID", "123", "/T", "/F"],
            check=False,
            stdout=strix_runner.subprocess.DEVNULL,
            stderr=strix_runner.subprocess.DEVNULL,
        )
        process.wait.assert_called_once_with(timeout=10)

    @mock.patch("strix_runner.subprocess.run", side_effect=OSError("taskkill missing"))
    def test_process_tree_falls_back_to_parent_kill(self, run):
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        managed = strix_runner.ManagedProcess(process, None)
        with mock.patch("strix_runner.os.name", "nt"):
            strix_runner.terminate_process_tree(managed, "app")
        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=10)

    @mock.patch("strix_runner.process_group_exists", return_value=True)
    @mock.patch("strix_runner.os.killpg")
    def test_posix_cleanup_kills_group_even_when_parent_has_exited(
        self, killpg, group_exists
    ):
        process = mock.Mock(pid=123)
        process.poll.return_value = 0
        managed = strix_runner.ManagedProcess(process, 123)
        with mock.patch("strix_runner.os.name", "posix"), mock.patch(
            "strix_runner.os.getpgrp", return_value=999
        ):
            strix_runner.terminate_process_tree(managed, "app", grace_seconds=0)

        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(123, strix_runner.signal.SIGTERM),
                mock.call(123, strix_runner.signal.SIGKILL),
            ],
        )
        group_exists.assert_called_with(123)

    @mock.patch("strix_runner.process_group_exists", return_value=False)
    @mock.patch("strix_runner.os.killpg")
    def test_posix_cleanup_stops_after_group_exits(self, killpg, group_exists):
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        managed = strix_runner.ManagedProcess(process, 123)
        with mock.patch("strix_runner.os.name", "posix"), mock.patch(
            "strix_runner.os.getpgrp", return_value=999
        ):
            strix_runner.terminate_process_tree(managed, "app", grace_seconds=10)

        killpg.assert_called_once_with(123, strix_runner.signal.SIGTERM)
        group_exists.assert_called_once_with(123)

    @mock.patch("strix_runner.os.killpg")
    def test_posix_cleanup_never_signals_runner_group(self, killpg):
        process = mock.Mock(pid=123)
        process.poll.return_value = None
        managed = strix_runner.ManagedProcess(process, 456)
        with mock.patch("strix_runner.os.name", "posix"), mock.patch(
            "strix_runner.os.getpgrp", return_value=456
        ):
            strix_runner.terminate_process_tree(managed, "app", grace_seconds=0)

        killpg.assert_not_called()
        process.terminate.assert_called_once_with()

    @mock.patch("strix_runner.subprocess.Popen")
    def test_start_managed_process_disconnects_stdin_and_records_pgid(self, popen):
        process = mock.Mock(pid=123)
        popen.return_value = process
        with mock.patch("strix_runner.os.name", "posix"), mock.patch(
            "strix_runner.os.getpgid", return_value=123
        ):
            managed = strix_runner.start_managed_process(
                ["npm", "start"], self.base, None
            )

        self.assertEqual(managed, strix_runner.ManagedProcess(process, 123))
        popen.assert_called_once_with(
            ["npm", "start"],
            cwd=self.base,
            stdin=strix_runner.subprocess.DEVNULL,
            stdout=None,
            stderr=strix_runner.subprocess.STDOUT,
            start_new_session=True,
        )

    @mock.patch("builtins.input", return_value="2,1,2")
    def test_interactive_selector_sorts_and_deduplicates(self, input_):
        applications = {
            "zeta": {"url": "https://zeta.example.test"},
            "alpha": {"code_path": "src/alpha"},
        }
        with mock.patch.object(strix_runner.sys.stdin, "isatty", return_value=True):
            selected = strix_runner.choose_applications(applications)
        self.assertEqual(selected, ["zeta", "alpha"])

    def test_application_selectors_accept_ids_names_and_commas(self):
        applications = {
            "zeta": {"url": "https://zeta.example.test"},
            "alpha": {"code_path": "src/alpha"},
            "beta": {"url": "https://beta.example.test"},
        }

        selected = strix_runner.resolve_application_selectors(
            applications, ["3,1", "beta", "3"]
        )

        self.assertEqual(selected, ["zeta", "alpha", "beta"])

    def test_application_selector_rejects_unknown_id(self):
        with self.assertRaisesRegex(
            strix_runner.UserError, "ID de aplicación fuera de rango: 2"
        ):
            strix_runner.resolve_application_selectors(
                {"app": {"url": "https://example.test"}}, ["2"]
            )

    def test_list_displays_selection_ids_in_alphabetical_order(self):
        self.config["applications"]["alpha"] = {
            "url": "https://alpha.example.test"
        }
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        output = io.StringIO()

        with redirect_stdout(output):
            status = strix_runner.list_applications(
                SimpleNamespace(config=config_path, json=False)
            )

        self.assertEqual(status, 0)
        text = output.getvalue()
        self.assertLess(text.index("[1] alpha:"), text.index("[2] app:"))
        self.assertIn("Ejemplo de ejecución por ID:", text)
        self.assertIn("strix_runner run 1,2", text)
        self.assertIn("Selecciona: [1] alpha, [2] app", text)

    def test_list_example_only_references_existing_single_application(self):
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        output = io.StringIO()

        with redirect_stdout(output):
            strix_runner.list_applications(
                SimpleNamespace(config=config_path, json=False)
            )

        text = output.getvalue()
        self.assertIn("strix_runner run 1", text)
        self.assertIn("Selecciona: [1] app", text)

    @mock.patch("strix_runner.run_application", return_value=0)
    def test_run_applications_resolves_numeric_ids(self, run_application):
        self.config["applications"]["alpha"] = {
            "url": "https://alpha.example.test"
        }
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        args = SimpleNamespace(
            config=config_path,
            all=False,
            names=["2,1"],
            keep_going=False,
        )

        status = strix_runner.run_applications(args)

        self.assertEqual(status, 0)
        selected_names = [call.args[1] for call in run_application.call_args_list]
        self.assertEqual(selected_names, ["app", "alpha"])

    def test_parser_accepts_run_control_flags(self):
        args = strix_runner.make_parser().parse_args(
            [
                "run",
                "app",
                "--keep-going",
                "--skip-start",
                "--non-interactive",
                "--code-mode",
                "exclude",
                "--additional-instruction-file",
                "extra.md",
                "--app-log-dir",
                "run-logs",
                "--report-summary",
                "full",
            ]
        )
        self.assertEqual(args.names, ["app"])
        self.assertTrue(args.keep_going)
        self.assertTrue(args.skip_start)
        self.assertTrue(args.non_interactive)
        self.assertEqual(args.code_mode, "exclude")
        self.assertEqual(args.additional_instruction_file, Path("extra.md"))
        self.assertEqual(args.app_log_dir, Path("run-logs"))
        self.assertEqual(args.report_summary, "full")
        self.assertIsNone(args.target_mode)

    def test_parser_accepts_only_code(self):
        args = strix_runner.make_parser().parse_args(["run", "app", "--only-code"])
        self.assertEqual(args.target_mode, "code")

    def test_parser_accepts_only_pentesting(self):
        args = strix_runner.make_parser().parse_args(
            ["run", "app", "--only-pentesting"]
        )
        self.assertEqual(args.target_mode, "pentesting")

    def test_target_modes_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            strix_runner.make_parser().parse_args(
                ["run", "app", "--only-code", "--only-pentesting"]
            )

    def test_only_code_skips_project_lifecycle_in_dry_run(self):
        code_path = self.base / "source code/app"
        code_path.mkdir(parents=True)
        self.config["applications"]["app"]["start_command"] = "python -m demo"
        args = SimpleNamespace(
            code_mode="auto",
            target_mode="code",
            non_interactive=False,
            no_validate=True,
            additional_instruction_file=None,
            skip_start=False,
            dry_run=True,
            app_log_dir=self.base / "logs",
            log_run_id="run-id",
        )
        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.run_application(self.config, "app", args)
        self.assertEqual(status, 0)
        self.assertNotIn("arranque", output.getvalue())
        self.assertNotIn("application.log", output.getvalue())

    def test_version_subcommand(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.main(["version"])
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue().strip(), "strix-runner 1.11.0")

    def test_version_option(self):
        output = io.StringIO()
        with self.assertRaises(SystemExit) as raised:
            with redirect_stdout(output):
                strix_runner.main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), "strix-runner 1.11.0")

    def test_verify_json_only_does_not_require_existing_paths(self):
        path = self.base / "config.json"
        self.config["globals"] = {
            "path_base": "/path/that/does/not/exist",
            "path_strix": "/another/missing/path",
        }
        strix_runner.save_config(path, self.config)
        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.verify_configuration(
                SimpleNamespace(config=path, json_only=True)
            )
        self.assertEqual(status, 0)
        self.assertIn("estructura JSON", output.getvalue())
        self.assertIn("Aplicaciones válidas: 1", output.getvalue())

    def test_verify_checks_referenced_paths(self):
        path = self.base / "config.json"
        strix_runner.save_config(path, self.config)
        with self.assertRaisesRegex(strix_runner.UserError, "instruction_file"):
            strix_runner.verify_configuration(
                SimpleNamespace(config=path, json_only=False)
            )

    def test_verify_accepts_valid_runtime_paths(self):
        for relative in (
            "instructions/a file.md",
            "token.json",
            "mail otp.py",
            "source code/app",
        ):
            path = self.base / relative
            if Path(relative).suffix:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            else:
                path.mkdir(parents=True, exist_ok=True)
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.verify_configuration(
                SimpleNamespace(config=config_path, json_only=False)
            )
        self.assertEqual(status, 0)
        self.assertIn("estructura JSON y rutas", output.getvalue())

    def test_verify_checks_every_code_path(self):
        profile = self.config["applications"]["app"]
        profile.pop("code_path")
        profile["code_paths"] = ["frontend", "missing-backend"]
        for relative in (
            "instructions/a file.md",
            "token.json",
            "mail otp.py",
        ):
            path = self.base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        (self.base / "frontend").mkdir()
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        with self.assertRaisesRegex(strix_runner.UserError, "missing-backend"):
            strix_runner.verify_configuration(
                SimpleNamespace(config=config_path, json_only=False)
            )

    def test_save_persists_repeated_urls_and_code_paths(self):
        config_path = self.base / "config.json"
        config = strix_runner.empty_config()
        config["globals"] = self.config["globals"]
        strix_runner.save_config(config_path, config)
        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.main(
                [
                    "--config",
                    str(config_path),
                    "save",
                    "multi",
                    "-u",
                    "https://frontend.example.test",
                    "-u",
                    "https://api.example.test",
                    "-c",
                    "frontend",
                    "-c",
                    "backend",
                    "--additional-instruction-file",
                    "Instrucciones/skill-audit.md",
                    "--stop-grace-seconds",
                    "15",
                ]
            )
        self.assertEqual(status, 0)
        profile = strix_runner.load_config(config_path)["applications"]["multi"]
        self.assertEqual(
            profile["urls"],
            ["https://frontend.example.test", "https://api.example.test"],
        )
        self.assertEqual(profile["code_paths"], ["frontend", "backend"])
        self.assertEqual(
            profile["additional_instruction_file"],
            "Instrucciones/skill-audit.md",
        )
        self.assertEqual(profile["stop_grace_seconds"], 15.0)

        with redirect_stdout(io.StringIO()):
            clear_status = strix_runner.main(
                [
                    "--config",
                    str(config_path),
                    "save",
                    "multi",
                    "--clear-additional-instruction-file",
                ]
            )
        self.assertEqual(clear_status, 0)
        cleared = strix_runner.load_config(config_path)["applications"]["multi"]
        self.assertNotIn("additional_instruction_file", cleared)

    def test_stored_additional_instruction_is_relative_to_path_base(self):
        self.config["applications"]["app"][
            "additional_instruction_file"
        ] = "instructions/extra.md"
        resolved = strix_runner.additional_instruction_path(
            self.config,
            "app",
            None,
        )
        self.assertEqual(resolved, self.base / "instructions/extra.md")

    def test_run_additional_instruction_overrides_stored_path(self):
        self.config["applications"]["app"][
            "additional_instruction_file"
        ] = "instructions/stored.md"
        override = Path("runtime-extra.md")
        resolved = strix_runner.additional_instruction_path(
            self.config,
            "app",
            override,
        )
        self.assertEqual(resolved, override)

    def test_verify_checks_stored_additional_instruction(self):
        for relative in (
            "instructions/a file.md",
            "token.json",
            "mail otp.py",
            "source code/app",
        ):
            path = self.base / relative
            if Path(relative).suffix:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            else:
                path.mkdir(parents=True, exist_ok=True)
        self.config["applications"]["app"][
            "additional_instruction_file"
        ] = "instructions/missing-extra.md"
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        with self.assertRaisesRegex(
            strix_runner.UserError, "additional_instruction_file"
        ):
            strix_runner.verify_configuration(
                SimpleNamespace(config=config_path, json_only=False)
            )

    def test_additional_instruction_is_combined_and_temporary(self):
        configured = self.base / "configured.md"
        additional = self.base / "additional.md"
        configured.write_text("Base instruction", encoding="utf-8")
        additional.write_text("Runtime instruction", encoding="utf-8")
        command = ["uv", "run", "strix", "--instruction-file", str(configured)]

        with strix_runner.command_with_additional_instruction(
            command, additional
        ) as combined:
            self.assertEqual(combined.count("--instruction-file"), 1)
            combined_path = Path(combined[combined.index("--instruction-file") + 1])
            self.assertTrue(combined_path.exists())
            text = combined_path.read_text(encoding="utf-8")
            self.assertIn("Base instruction", text)
            self.assertIn("Runtime instruction", text)
            self.assertNotEqual(combined_path, configured)

        self.assertFalse(combined_path.exists())
        self.assertEqual(
            configured.read_text(encoding="utf-8"),
            "Base instruction",
        )

    def test_additional_instruction_rejects_empty_file(self):
        additional = self.base / "empty.md"
        additional.touch()
        with self.assertRaisesRegex(strix_runner.UserError, "está vacío"):
            with strix_runner.command_with_additional_instruction(
                ["uv", "run", "strix"], additional
            ):
                self.fail("The context should not be entered")

    def test_additional_instruction_rejects_conflicting_strix_argument(self):
        additional = self.base / "additional.md"
        additional.write_text("Runtime instruction", encoding="utf-8")
        command = [
            "uv",
            "run",
            "strix",
            "--instruction-file=configured.md",
        ]
        with self.assertRaisesRegex(strix_runner.UserError, "--strix-arg"):
            with strix_runner.command_with_additional_instruction(
                command, additional
            ):
                self.fail("The context should not be entered")

    def test_history_collects_agents_skills_and_explicit_utility(self):
        run_dir, _ = self.write_strix_run(
            targets=[
                "https://example.test/app",
                str(self.base / "source code/app"),
            ],
            findings=[{"severity": "high"}],
        )
        state_dir = run_dir / ".state"
        state_dir.mkdir()
        (state_dir / "agents.json").write_text(
            json.dumps(
                {
                    "statuses": {"agent-1": "completed"},
                    "names": {"agent-1": "source-review"},
                    "metadata": {
                        "agent-1": {
                            "task": "Review the source",
                            "skills": ["secure-review", "threat-model"],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        (state_dir / "skill_audit.json").write_text(
            json.dumps(
                [
                    {
                        "agent_id": "agent-1",
                        "skill": "secure-review",
                        "rating": "high",
                        "reason": "Guided the source-to-sink analysis.",
                        "evidence": ["message-12"],
                    }
                ]
            ),
            encoding="utf-8",
        )

        runs = strix_runner.collect_history_runs(self.config, profile="app")

        self.assertEqual(len(runs), 1)
        run = runs[0]
        self.assertEqual(run.profile, "app")
        self.assertEqual(run.profile_source, "reconstructed")
        self.assertEqual(run.findings, 1)
        self.assertEqual(run.severity_counts["high"], 1)
        self.assertEqual(len(run.agents), 1)
        self.assertEqual(run.agents[0].name, "source-review")
        self.assertEqual(run.agents[0].skills[0].utility, "high")
        self.assertEqual(
            run.agents[0].skills[1].utility,
            "not_observable",
        )

    def test_history_run_dir_relative(self):
        run_dir, _ = self.write_strix_run(targets=["https://example.test/app"])
        runs = strix_runner.collect_history_runs(self.config, profile="app")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].run_dir, str(run_dir))
        self.assertEqual(runs[0].run_dir_relative, "strix_runs/example-run")

    def test_history_collects_models(self):
        run_dir, _ = self.write_strix_run(
            targets=["https://example.test/app"],
            models=["openai/gpt-4o", "openai/gpt-4o-mini", "openai/gpt-4o"],
        )
        runs = strix_runner.collect_history_runs(self.config, profile="app")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].models, ["openai/gpt-4o", "openai/gpt-4o-mini"])

    def test_history_models_empty_when_not_present(self):
        run_dir, _ = self.write_strix_run(targets=["https://example.test/app"])
        runs = strix_runner.collect_history_runs(self.config, profile="app")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].models, [])

    def test_history_filters_dates_and_marks_reconstructed_command(self):
        self.write_strix_run(targets=["https://example.test/app"])

        included = strix_runner.collect_history_runs(
            self.config,
            profile="app",
            from_date=date(2026, 10, 5),
            to_date=date(2026, 10, 5),
        )
        excluded = strix_runner.collect_history_runs(
            self.config,
            profile="app",
            from_date=date(2026, 10, 6),
        )

        self.assertEqual(len(included), 1)
        self.assertEqual(included[0].command_source, "reconstructed")
        self.assertIn("extra_args", included[0].command_gaps)
        self.assertEqual(excluded, [])

    def test_history_assigns_and_resolves_chronological_ids(self):
        old_dir, old_record = self.write_strix_run(
            "old-run",
            targets=["https://example.test/app"],
        )
        old_record["run_id"] = "persisted-old"
        old_record["start_time"] = "2026-10-04T10:00:00+00:00"
        (old_dir / "run.json").write_text(
            json.dumps(old_record),
            encoding="utf-8",
        )
        new_dir, new_record = self.write_strix_run(
            "new-run",
            targets=["https://example.test/app"],
        )
        new_record["run_id"] = "persisted-new"
        new_record["start_time"] = "2026-10-06T10:00:00+00:00"
        (new_dir / "run.json").write_text(
            json.dumps(new_record),
            encoding="utf-8",
        )

        runs = strix_runner.collect_history_runs(self.config, profile="app")
        selected = strix_runner.collect_history_runs(
            self.config,
            profile="app",
            run_selector="2",
        )

        self.assertEqual(
            [(run.selection_id, run.run_id) for run in runs],
            [(1, "persisted-new"), (2, "persisted-old")],
        )
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].selection_id, 2)
        self.assertEqual(selected[0].run_id, "persisted-old")
        with self.assertRaisesRegex(strix_runner.UserError, "fuera de rango"):
            strix_runner.collect_history_runs(
                self.config,
                profile="app",
                run_selector="3",
            )

    def test_history_uses_captured_profile_and_command(self):
        run_dir, _ = self.write_strix_run(targets=["https://old.example.test"])
        strix_runner.atomic_private_text(
            run_dir / "strix-runner.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "profile": "legacy-app",
                    "commands": {
                        "strix": {
                            "argv": ["uv", "run", "strix", "--target", "legacy"],
                            "cwd": str(self.strix),
                        }
                    },
                    "skill_audit": [],
                }
            ),
        )

        runs = strix_runner.collect_history_runs(
            self.config,
            profile="legacy-app",
        )

        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].profile_source, "captured")
        self.assertEqual(runs[0].command_source, "captured")
        self.assertEqual(runs[0].command[:3], ["uv", "run", "strix"])

    def test_history_html_is_standalone_and_escapes_embedded_data(self):
        payload = {
            "runner_version": "1.10.0",
            "generated_at": "2026-10-08T12:00:00+02:00",
            "filters": {"profile": None, "from": None, "to": None},
            "summary": {
                "runs": 0,
                "findings": 0,
                "agents": 0,
                "skills": 0,
                "total_tokens": 0,
            },
            "runs": [],
            "untrusted": "</script><script>alert(1)</script>",
        }

        html = strix_runner.standalone_history_html(payload)

        self.assertIn("<!doctype html>", html)
        self.assertNotIn("</script><script>alert(1)</script>", html)
        self.assertIn("\\u003c/script\\u003e", html)
        self.assertNotIn("<link", html)

    def test_history_command_writes_private_html(self):
        self.write_strix_run(targets=["https://example.test/app"])
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        destination = self.base / "exports" / "history.html"
        args = SimpleNamespace(
            config=config_path,
            name="app",
            all=False,
            from_date=None,
            to_date=None,
            run=None,
            details=False,
            json=False,
            html=destination,
        )

        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.show_history(args)

        self.assertEqual(status, 0)
        self.assertTrue(destination.is_file())
        self.assertIn("Historial HTML guardado", output.getvalue())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_parser_accepts_history_export(self):
        args = strix_runner.make_parser().parse_args(
            [
                "history",
                "app",
                "--from",
                "2026-10-01",
                "--to",
                "2026-10-08",
                "--details",
                "--html",
                "history.html",
            ]
        )

        self.assertEqual(args.name, "app")
        self.assertEqual(args.from_date, "2026-10-01")
        self.assertEqual(args.to_date, "2026-10-08")
        self.assertTrue(args.details)
        self.assertEqual(args.html, Path("history.html"))

    def test_history_id_forms_imply_complete_history(self):
        self.write_strix_run(targets=["https://example.test/app"])
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        base = {
            "config": config_path,
            "all": False,
            "from_date": None,
            "to_date": None,
            "details": False,
            "json": False,
            "html": None,
        }
        for name, run_selector in (("1", None), (None, "1")):
            args = SimpleNamespace(
                **base,
                name=name,
                run=run_selector,
            )
            output = io.StringIO()
            with redirect_stdout(output):
                status = strix_runner.show_history(args)
            self.assertEqual(status, 0)
            self.assertIn("[ 1]", output.getvalue())

        parsed = strix_runner.make_parser().parse_args(["history", "--id", "1"])
        self.assertEqual(parsed.run, "1")
        self.assertIsNone(parsed.name)

    def test_resume_list_only_shows_runs_with_complete_agent_state(self):
        resumable_dir, _ = self.write_strix_run("resumable-run")
        self.write_resume_state(resumable_dir)
        self.write_strix_run("missing-state-run")
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        args = SimpleNamespace(
            config=config_path,
            selector="list",
            non_interactive=False,
            dry_run=False,
        )

        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.resume_run(args)

        self.assertEqual(status, 0)
        self.assertIn("resumable-run", output.getvalue())
        self.assertNotIn("missing-state-run", output.getvalue())

    def test_resumable_runs_keep_ids_from_complete_history(self):
        resumable_dir, resumable_record = self.write_strix_run("resumable-run")
        resumable_record["start_time"] = "2026-10-04T10:00:00+00:00"
        (resumable_dir / "run.json").write_text(
            json.dumps(resumable_record),
            encoding="utf-8",
        )
        self.write_resume_state(resumable_dir)
        newest_dir, newest_record = self.write_strix_run("newest-without-state")
        newest_record["start_time"] = "2026-10-06T10:00:00+00:00"
        (newest_dir / "run.json").write_text(
            json.dumps(newest_record),
            encoding="utf-8",
        )

        runs = strix_runner.resumable_history_runs(self.config)

        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].run_name, "resumable-run")
        self.assertEqual(runs[0].selection_id, 2)

    def test_resume_rejects_run_without_sdk_session_database(self):
        run_dir, _ = self.write_strix_run()
        state_dir = run_dir / ".state"
        state_dir.mkdir()
        (state_dir / "agents.json").write_text("{}", encoding="utf-8")

        with self.assertRaisesRegex(strix_runner.UserError, "agents.db"):
            strix_runner.resolve_resume_run(self.config, "1")

    @mock.patch("strix_runner.subprocess.run")
    def test_resume_executes_native_strix_resume_by_history_id(self, run):
        run.return_value = SimpleNamespace(returncode=0)
        run_dir, _ = self.write_strix_run()
        self.write_resume_state(run_dir)
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        args = SimpleNamespace(
            config=config_path,
            selector="1",
            non_interactive=False,
            dry_run=False,
        )

        status = strix_runner.resume_run(args)

        self.assertEqual(status, 0)
        run.assert_called_once_with(
            ["uv", "run", "strix", "--resume", "example-run"],
            cwd=self.strix,
            check=False,
        )

    @mock.patch("strix_runner.subprocess.run")
    def test_resume_dry_run_can_show_non_interactive_command(self, run):
        run_dir, _ = self.write_strix_run()
        self.write_resume_state(run_dir)
        config_path = self.base / "config.json"
        strix_runner.save_config(config_path, self.config)
        args = SimpleNamespace(
            config=config_path,
            selector="example-run",
            non_interactive=True,
            dry_run=True,
        )

        output = io.StringIO()
        with redirect_stdout(output):
            status = strix_runner.resume_run(args)

        self.assertEqual(status, 0)
        self.assertIn(
            "uv run strix --non-interactive --resume example-run",
            output.getvalue(),
        )
        run.assert_not_called()

    def test_parser_accepts_resume_list_and_history_id(self):
        listed = strix_runner.make_parser().parse_args(["resume", "list"])
        resumed = strix_runner.make_parser().parse_args(
            ["resume", "3", "--dry-run", "--non-interactive"]
        )

        self.assertEqual(listed.selector, "list")
        self.assertIs(listed.handler, strix_runner.resume_run)
        self.assertEqual(resumed.selector, "3")
        self.assertTrue(resumed.dry_run)
        self.assertTrue(resumed.non_interactive)


if __name__ == "__main__":
    unittest.main()
