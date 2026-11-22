"""Tests for check_workflow_permissions.py. Each defect is planted and must be reported."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[1]
CHECK = HERE / "check_workflow_permissions.py"
sys.path.insert(0, str(HERE))
import check_workflow_permissions as c  # noqa: E402

REUSABLE = "name: x\non:\n  workflow_call:\n    inputs: {}\n@PERM@jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps: []\n"


def run(root):
    return subprocess.run([sys.executable, str(CHECK), str(root)], capture_output=True, text=True)


class Unit(unittest.TestCase):
    def test_missing_permissions_is_flagged(self):
        self.assertEqual(len(c.check_text(REUSABLE.replace("@PERM@", ""))), 1)

    def test_declared_permissions_pass(self):
        self.assertEqual(c.check_text(REUSABLE.replace("@PERM@", "permissions:\n  contents: read\n")), [])

    def test_write_all_is_flagged(self):
        self.assertEqual(len(c.check_text(REUSABLE.replace("@PERM@", "permissions: write-all\n"))), 1)

    def test_empty_permissions_map_passes(self):
        self.assertEqual(c.check_text(REUSABLE.replace("@PERM@", "permissions: {}\n")), [])

    def test_job_level_permissions_do_not_count(self):
        t = "on:\n  workflow_call:\njobs:\n  a:\n    permissions:\n      contents: read\n    runs-on: x\n"
        self.assertEqual(len(c.check_text(t)), 1)

    def test_commented_permissions_do_not_count(self):
        self.assertEqual(len(c.check_text(REUSABLE.replace("@PERM@", "# permissions:\n#   contents: read\n"))), 1)

    def test_flow_and_scalar_on_forms_are_detected(self):
        for on in ("on: [push, workflow_call]\n", "on: workflow_call\n"):
            self.assertEqual(len(c.check_text(on + "jobs: {}\n")), 1, on)

    def test_quoted_and_yaml11_on_keys_are_detected(self):
        for on in ('"on":\n  workflow_call:\n', "'on':\n  workflow_call:\n", "true:\n  workflow_call:\n",
                   '"on": workflow_call\n'):
            self.assertEqual(len(c.check_text(on + "jobs: {}\n")), 1, on)

    def test_quoted_write_all_is_flagged(self):
        for v in ('"write-all"', "'write-all'"):
            self.assertEqual(len(c.check_text(REUSABLE.replace("@PERM@", "permissions: %s\n" % v))), 1, v)

    def test_quoted_permissions_key_counts_as_declared(self):
        self.assertEqual(c.check_text(REUSABLE.replace("@PERM@", '"permissions":\n  contents: read\n')), [])

    def test_non_reusable_workflow_is_ignored(self):
        self.assertEqual(c.check_text("on:\n  push:\njobs: {}\n"), [])

    def test_workflow_call_in_a_comment_is_not_reusable(self):
        self.assertEqual(c.check_text("# on: workflow_call\non:\n  push:\njobs: {}\n"), [])


class Cli(unittest.TestCase):
    def _repo(self, files):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        w = pathlib.Path(d.name) / ".github" / "workflows"
        w.mkdir(parents=True)
        for name, text in files.items():
            (w / name).write_text(text)
        return d.name

    def test_violation_exits_1(self):
        self.assertEqual(run(self._repo({"r.yml": REUSABLE.replace("@PERM@", "")})).returncode, 1)

    def test_conforming_exits_0(self):
        self.assertEqual(run(self._repo({"r.yml": REUSABLE.replace("@PERM@", "permissions:\n  contents: read\n")})).returncode, 0)

    def test_no_reusable_workflow_exits_2(self):
        self.assertEqual(run(self._repo({"ci.yml": "on:\n  push:\njobs: {}\n"})).returncode, 2)

    def test_this_repo_conforms(self):
        r = run(REPO)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
