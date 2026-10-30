import os
import shlex
import unittest

from graphenex.core.hrd.exec import (
    CommandResult,
    LinuxExec,
    WinExec,
    build_argv,
    sanitized_env,
)
from tests.support import workdir


class BuildArgvTests(unittest.TestCase):
    def test_rejects_empty_command(self):
        with self.assertRaises(ValueError):
            build_argv("   ")

    def test_rejects_unbalanced_quotes_without_shell(self):
        with self.assertRaises(ValueError):
            build_argv("echo 'unterminated")

    def test_allows_unbalanced_quotes_with_shell(self):
        self.assertEqual(build_argv("echo 'x", shell=True), "echo 'x")

    def test_expands_only_known_variables(self):
        os.environ["USER"] = "gx-user"
        self.addCleanup(os.environ.pop, "USER", None)
        argv = build_argv("echo $USER $(id)")
        self.assertEqual(argv, ["echo", "gx-user", "$(id)"])

    def test_rejects_nul_bytes(self):
        with self.assertRaises(ValueError):
            build_argv("echo\x00boom")


class SanitizedEnvTests(unittest.TestCase):
    def test_removes_code_injection_variables(self):
        os.environ["LD_PRELOAD"] = "/tmp/evil.so"
        os.environ["BASH_ENV"] = "/tmp/evil.sh"
        self.addCleanup(os.environ.pop, "LD_PRELOAD", None)
        self.addCleanup(os.environ.pop, "BASH_ENV", None)
        env = sanitized_env()
        self.assertNotIn("LD_PRELOAD", env)
        self.assertNotIn("BASH_ENV", env)
        self.assertEqual(env["LC_ALL"], "C")


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.exec = LinuxExec()

    def test_success(self):
        result = self.exec.run_cmd("echo hello")
        self.assertIsInstance(result, CommandResult)
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout.strip(), "hello")
        self.assertEqual(result.returncode, 0)

    @unittest.skipIf(os.name == "nt", "POSIX only")
    def test_non_zero_exit_is_reported_not_raised(self):
        result = self.exec.run_cmd("sh -c 'echo bad >&2; exit 3'")
        self.assertFalse(result.ok)
        self.assertEqual(result.returncode, 3)
        self.assertIn("bad", result.stderr)

    @unittest.skipIf(os.name == "nt", "POSIX only")
    def test_missing_executable(self):
        result = self.exec.run_cmd("graphenex-executable-that-does-not-exist")
        self.assertEqual(result.returncode, 127)
        self.assertIn("not found", result.error)

    @unittest.skipIf(os.name == "nt", "POSIX only")
    def test_timeout_kills_the_process(self):
        result = self.exec.run_cmd("sh -c 'sleep 30'", timeout=0.5)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)
        self.assertLess(result.duration, 10)

    @unittest.skipIf(os.name == "nt", "POSIX only")
    def test_shell_redirection_requires_shell_opt_in(self):
        target = workdir(self) / "out.txt"
        plain = self.exec.run_cmd("echo hi > " + str(target))
        self.assertFalse(target.exists())
        self.assertIn(">", plain.stdout)

        shell = self.exec.run_cmd("echo hi > " + str(target), shell=True)
        self.assertTrue(shell.ok)
        self.assertEqual(target.read_text().strip(), "hi")

    @unittest.skipIf(os.name == "nt", "POSIX only")
    def test_metacharacters_are_not_interpreted_without_shell(self):
        directory = workdir(self)
        canary = directory / "pwned"
        weird = directory / ("a; touch " + canary.name)
        weird.write_text("data")
        result = self.exec.run_cmd("cat " + shlex.quote(str(weird)))
        self.assertTrue(result.ok)
        self.assertFalse(canary.exists(), "argv mode must not spawn a second command")

    def test_dry_run_does_not_execute(self):
        directory = workdir(self)
        target = directory / "should-not-exist"
        result = self.exec.run_cmd("touch " + str(target), dry_run=True)
        self.assertTrue(result.ok)
        self.assertTrue(result.dry_run)
        self.assertFalse(target.exists())

    @unittest.skipIf(os.name == "nt", "POSIX only")
    def test_stdin_is_supported(self):
        result = self.exec.run_cmd("cat", input_text="piped data")
        self.assertTrue(result.ok)
        self.assertEqual(result.stdout, "piped data")

    def test_invalid_timeout_falls_back_to_default(self):
        self.assertEqual(self.exec._timeout("nonsense"), 120.0)
        self.assertEqual(self.exec._timeout(-1), 120.0)
        self.assertEqual(self.exec._timeout(999999), 3600.0)

    def test_windows_executor_exists(self):
        self.assertEqual(WinExec().os_name, "win")
