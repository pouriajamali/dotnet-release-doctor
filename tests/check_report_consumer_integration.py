"""Independent sentinel integration. Execute only an existing trusted Doctor binary."""
import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("consumer", ROOT / "examples/consume_report.py")
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
SENTINEL = "TRIPWIRE_ENTRY_EXECUTED"


def hashes(folder):
    return {p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*")) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--doctor", required=True, type=Path)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    # A separate synthetic target writes the sentinel if its real entry executes.
    # We never invoke its apphost, DLL, script or installed dotnet host.
    assert SENTINEL.encode("utf-16le") in (args.fixture / "Tripwire.dll").read_bytes()
    rows = []
    for name, expected in (("selected-pass", 0), ("version-mismatch", 2), ("unsupported", 1)):
        target = args.work / (name + "-target")
        shutil.copytree(args.fixture, target)
        if name == "unsupported":
            config = target / "Tripwire.runtimeconfig.json"
            config.write_text(json.dumps({"runtimeOptions": {"includedFrameworks": []}}), encoding="utf-8")
        before = hashes(target)
        output = args.work / (name + "-report")
        command = [str(args.doctor), "inspect", str(target), str(output), "--entry", "Tripwire.dll", "--rid", "win-x64"]
        if name == "version-mismatch":
            command += ["--expected-version", "99.99.99"]
        process = subprocess.run(command, cwd=target, capture_output=True, timeout=20)
        (args.work / (name + ".stdout")).write_bytes(process.stdout)
        (args.work / (name + ".stderr")).write_bytes(process.stderr)
        assert process.returncode == expected, (name, process.returncode)
        result, decision = consumer.consume(output / "summary.json", process.returncode)
        assert decision == expected, (name, result)
        if name == "selected-pass":
            assert result["checks"][-1]["status"] == "not_checked"
            policy, policy_exit = consumer.consume(output / "summary.json", process.returncode, ["inventory"])
            assert policy_exit == 1 and policy["inspectorExit"] == 0
        if name == "unsupported":
            assert result["reason"] == "SELF_CONTAINED_UNSUPPORTED"
            assert result["inspectorOutcome"] == "incomplete"
        assert not (target / SENTINEL).exists()
        assert before == hashes(target), "Doctor modified target contents or executed sentinel entry"
        rows.append({"case": name, "doctorExit": process.returncode, "consumerExit": decision,
                     "reason": result["reason"], "targetHashes": before, "sentinelAbsent": True,
                     "hashesUnchanged": True})
    receipt = {"status": "PASS", "scope": "Existing Linux Doctor inspects synthetic win-x64 FDD; no target execution", "cases": rows}
    (args.work / "integration.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS", "cases": len(rows), "sentinelAbsent": True, "targetHashesUnchanged": True}))


if __name__ == "__main__":
    main()
