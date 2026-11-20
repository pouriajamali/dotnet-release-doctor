"""Source-only example: consume Doctor v1 JSON, never inspect or execute a target."""
import argparse
import json
import re
import stat
import sys
from pathlib import Path

IDS = ("runtime-config", "deps", "entry-metadata", "native-headers", "expected-version", "inventory")
ASSURANCES = {"inputProvenance": "UNVERIFIED", "installedRuntime": "NOT_CHECKED",
              "startup": "NOT_EXECUTED", "dependencyResolution": "NOT_PROVEN", "safety": "NOT_ASSESSED"}
MAX_BYTES = 65536


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate property")
        result[key] = value
    return result


def code(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", value):
        raise ValueError("invalid diagnostic")
    return value


def consume(path, doctor_exit, required=()):
    """Return a bounded projection and decision exit; input failures never pass."""
    try:
        if type(doctor_exit) is not int or doctor_exit not in (0, 1, 2):
            raise ValueError("invalid process exit")
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("not a regular report file")
        with path.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("report too large")
        report = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        if not isinstance(report, dict) or report.get("schema") != "release-doctor-report-v1":
            raise ValueError("unknown schema")
        outcome, complete, exit_code = (report.get(k) for k in ("outcome", "complete", "exitCode"))
        if type(complete) is not bool or type(exit_code) is not int:
            raise ValueError("invalid types")
        if (outcome, complete, exit_code) not in (("pass", True, 0), ("fail", True, 2), ("incomplete", False, 1)):
            raise ValueError("inconsistent outcome")
        if doctor_exit != exit_code or any(report.get(k) != v for k, v in ASSURANCES.items()):
            raise ValueError("exit or boundary mismatch")
        reason = code(report.get("reason"))
        checks = report.get("checks")
        if not isinstance(checks, list) or len(checks) != len(IDS):
            raise ValueError("missing checks")
        for expected, check in zip(IDS, checks):
            if not isinstance(check, dict) or set(check) != {"id", "status", "code"} or check["id"] != expected:
                raise ValueError("invalid check identity")
            if check["status"] not in ("pass", "fail", "not_checked"):
                raise ValueError("invalid check status")
            code(check["code"])
        if outcome == "pass":
            if reason != "SELECTED_STATIC_CHECKS_PASSED" or any(c["status"] != "pass" for c in checks[:4]):
                raise ValueError("inconsistent pass")
            if any(c["status"] == "fail" or (c["status"] == "not_checked" and c["code"] != "NOT_SELECTED") for c in checks[4:]):
                raise ValueError("inconsistent optional check")
        if outcome == "fail" and not any(c["status"] == "fail" for c in checks):
            raise ValueError("failure without failed check")
        if any(item not in IDS for item in required):
            raise ValueError("unknown required check")
        unmet = [c["id"] for c in checks if c["id"] in required and c["status"] != "pass"]
        decision = 1 if outcome == "pass" and unmet else exit_code
        return {"consumerSchema": "release-doctor-consumer-v1", "decisionExit": decision,
                "consumerReason": "REQUIRED_CHECK_NOT_PASSED" if outcome == "pass" and unmet else "REPORT_CONSUMED",
                "inspectorOutcome": outcome, "inspectorExit": exit_code, "reason": reason,
                "checks": checks, "unmetRequiredChecks": unmet, **ASSURANCES}, decision
    except (OSError, ValueError, TypeError, RecursionError):
        return {"consumerSchema": "release-doctor-consumer-v1", "decisionExit": 1,
                "consumerReason": "REPORT_INVALID_OR_EXIT_MISMATCH", **ASSURANCES}, 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path)
    parser.add_argument("--doctor-exit", type=int, required=True,
                        help="actual saved inspector process exit, not an assumed zero")
    parser.add_argument("--require", action="append", choices=IDS, default=[])
    args = parser.parse_args()
    result, exit_code = consume(args.summary, args.doctor_exit, args.require)
    print(json.dumps(result, separators=(",", ":"), ensure_ascii=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
