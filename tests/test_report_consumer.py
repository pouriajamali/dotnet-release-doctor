"""Consumer contract regressions; no target execution, SDK or network needed."""
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("consumer", ROOT / "examples/consume_report.py")
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


def golden():
    return {"schema": "release-doctor-report-v1", "complete": True, "outcome": "pass", "exitCode": 0,
            "reason": "SELECTED_STATIC_CHECKS_PASSED", **consumer.ASSURANCES,
            "checks": [{"id": name, "status": "pass" if i < 4 else "not_checked",
                        "code": "CHECKED" if i < 4 else "NOT_SELECTED"} for i, name in enumerate(consumer.IDS)]}


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "summary.json"

    def run_report(self, report, exit_code=0, required=()):
        self.path.write_text(json.dumps(report), encoding="utf-8")
        return consumer.consume(self.path, exit_code, required)

    def test_selected_pass_preserves_not_checked_and_boundaries(self):
        result, status = self.run_report(golden())
        self.assertEqual(status, 0)
        self.assertEqual(result["checks"][-1]["status"], "not_checked")
        for key, value in consumer.ASSURANCES.items():
            self.assertEqual(result[key], value)

    def test_explicit_inventory_policy_does_not_turn_not_checked_green(self):
        result, status = self.run_report(golden(), required=["inventory"])
        self.assertEqual(status, 1)
        self.assertEqual(result["inspectorExit"], 0)
        self.assertEqual(result["unmetRequiredChecks"], ["inventory"])
        report = golden()
        report["checks"][-1].update(status="pass", code="INVENTORY_AGREES_NOT_AUTHENTICATED")
        self.assertEqual(self.run_report(report, required=["inventory"])[1], 0)

    def test_completed_failure_is_two(self):
        report = golden()
        report.update(outcome="fail", exitCode=2, reason="EXPECTED_VERSION_MISMATCH")
        report["checks"][-2].update(status="fail", code="EXPECTED_VERSION_MISMATCH")
        result, status = self.run_report(report, 2)
        self.assertEqual(status, 2)
        self.assertEqual(result["inspectorOutcome"], "fail")

    def test_unsupported_is_incomplete_not_corrupt(self):
        report = golden()
        report.update(complete=False, outcome="incomplete", exitCode=1, reason="RID_UNSUPPORTED")
        for check in report["checks"]:
            check.update(status="not_checked", code="PREREQUISITE_NOT_MET")
        result, status = self.run_report(report, 1)
        self.assertEqual(status, 1)
        self.assertEqual(result["reason"], "RID_UNSUPPORTED")
        self.assertEqual(result["inspectorOutcome"], "incomplete")

    def test_exit_mismatch_and_invalid_process_exit(self):
        for exit_code in (1, 2, -9, True):
            with self.subTest(exit_code=exit_code):
                self.assertEqual(self.run_report(golden(), exit_code)[1], 1)

    def test_invalid_receipts_never_pass(self):
        for mutate in (lambda r: r.update(schema="future"), lambda r: r.update(complete=1),
                       lambda r: r.update(exitCode=False), lambda r: r.update(reason="injected\ntext"),
                       lambda r: r.update(startup="EXECUTED"), lambda r: r["checks"].pop(),
                       lambda r: r["checks"][0].update(status="not_checked"),
                       lambda r: r["checks"][-1].update(status="not_checked", code="PREREQUISITE_NOT_MET"),
                       lambda r: r["checks"][0].update(id="inventory")):
            report = copy.deepcopy(golden())
            mutate(report)
            self.assertEqual(self.run_report(report)[1], 1)

    def test_missing_duplicate_truncated_nonfinite_and_size_limit(self):
        self.assertEqual(consumer.consume(self.path, 0)[1], 1)
        for raw in ('{"schema":"release-doctor-report-v1","schema":"release-doctor-report-v1"}',
                    '{', '{"x":NaN}', '[' * 2000, ' ' * (consumer.MAX_BYTES + 1)):
            self.path.write_text(raw, encoding="utf-8")
            self.assertEqual(consumer.consume(self.path, 0)[1], 1)


if __name__ == "__main__":
    unittest.main()
