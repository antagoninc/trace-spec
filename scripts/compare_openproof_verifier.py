"""Compare the committed TRACE examples with a pinned upstream Go verifier.

Run with the checkout's development environment. The Go adapter composes native
approval checks for all five cases; the unmodified CLI covers complete histories.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

UPSTREAM = "d85c24a1ec9228de7c4876904f260a0093312b70"
FIXTURE_REVISION = "afc6e9acdb35a3f2f24f3aaf192ac802a91b0211"
ROOT = Path(__file__).resolve().parents[1]


def command(args: list[str], cwd: Path, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=180, **kwargs)


def require_clean_revision(path: Path, revision: str) -> None:
    head = command(["git", "rev-parse", "HEAD"], path)
    if head.returncode or head.stdout.strip() != revision:
        raise ValueError(f"{path} must be at {revision}")
    for args in (["git", "diff", "--exit-code"], ["git", "diff", "--cached", "--exit-code"]):
        result = command(args, path)
        if result.returncode:
            raise ValueError(f"tracked source modifications in {path}")
    status = command(
        ["git", "status", "--porcelain", "--untracked-files=all", "--", "reference/go-witness"],
        path,
    )
    if status.returncode or status.stdout:
        raise ValueError("upstream Go package must contain only its pinned tracked files")


def run_probe(go: str, go_dir: Path, work: Path, environment: dict, document: dict) -> dict:
    path = work / "probe-input.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    result = command(
        [go, "test", "-mod=readonly", "-count=1", "-run", "^TestTRACEReferenceProbe$", "-v"],
        go_dir,
        env={**environment, "OPENPROOF_COMPARISON_INPUT": str(path)},
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    lines = [line for line in result.stdout.splitlines() if line.startswith("TRACE_PROBE=")]
    if len(lines) != 1:
        raise ValueError("missing or ambiguous native probe result")
    return json.loads(lines[0].removeprefix("TRACE_PROBE="))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    upstream = args.upstream.resolve()
    require_clean_revision(upstream, UPSTREAM)
    fixtures = ROOT / "examples/openproof-approval-outcome"
    spec = importlib.util.spec_from_file_location(
        "fixture_assessment", ROOT / "tests/test_openproof_approval_outcome_fixtures.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = module.EXPECTED
    # Pin every input and the Python oracle to the reviewed PR head, even when
    # this runner itself is on a follow-up branch.
    inputs = sorted(fixtures.glob("*.json")) + [Path(spec.origin)]
    hashes = {}
    for path in inputs:
        relative = str(path.relative_to(ROOT))
        original = subprocess.run(
            ["git", "show", f"{FIXTURE_REVISION}:{relative}"],
            cwd=ROOT,
            capture_output=True,
            timeout=30,
            check=True,
        ).stdout
        if original != path.read_bytes():
            raise ValueError(f"input differs from pinned fixture revision: {relative}")
        hashes[relative] = hashlib.sha256(original).hexdigest()

    go_dir = upstream / "reference/go-witness"
    environment = {**os.environ, "GOTOOLCHAIN": "local"}
    tests = command(
        [args.go, "test", "-mod=readonly", "-count=1", "./..."], go_dir, env=environment
    )
    if tests.returncode:
        raise RuntimeError(tests.stdout + tests.stderr)
    rows = []
    with tempfile.TemporaryDirectory(prefix="openproof-comparison-") as directory:
        work = Path(directory)
        binary = work / "verify"
        probe_dir = work / "probe"
        probe_dir.mkdir()
        tracked = command(["git", "ls-files", "reference/go-witness"], upstream)
        tracked.check_returncode()
        for filename in tracked.stdout.splitlines():
            relative = Path(filename).relative_to("reference/go-witness")
            destination = probe_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(upstream / filename, destination)
        shim = ROOT / "scripts/openproof_comparison_probe_test.go"
        shutil.copyfile(shim, probe_dir / "trace_comparison_probe_test.go")
        build = command(
            [args.go, "build", "-trimpath", "-mod=readonly", "-o", str(binary), "."],
            go_dir,
            env=environment,
        )
        if build.returncode:
            raise RuntimeError(build.stdout + build.stderr)
        for name, case in expected["cases"].items():
            record = module._load(name)
            store = module._load(case["store"])
            python = module._assess(record, store)
            if python != {key: case[key] for key in module.OUTCOME_KEYS}:
                raise ValueError(f"Python assessment changed for {name}")
            module.verify_record(record, expected["trace_signer_jwk"], max_age_seconds=None)
            row = {"case": name, "python": python, "go": None}
            entry = store["entries"].get(record["references"][0]["id"])
            # Use one explicit historical time from the signed fixture checkpoint.
            epoch = max(
                item["checkpoint"]["payload"]["observed_at"]
                for item in store["entries"].values()
                if item.get("checkpoint") is not None
            )
            document = {
                "record": record,
                "store": store,
                "root_key": module.ROOT_KEY,
                "now": epoch,
            }
            probe = run_probe(args.go, probe_dir, work, environment, document)
            row["native_adapter"] = probe
            row["adapter_agrees"] = probe["verdict"] == python["verdict"]
            if name.startswith("05-") and probe.get("rejected_at") != "approval":
                raise ValueError("outside-trust fixture must fail before the passkey check")
            row["evaluation_epoch"] = epoch
            # Negative controls isolate native signature and passkey verification.
            # References are diagnostic unsigned copies when their digest changes.
            controls = []
            if name.startswith("03-"):
                bad_root = copy.deepcopy(document)
                bad_root["root_key"] = (
                    module.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
                    .public_key()
                    .public_bytes(module.Encoding.Raw, module.PublicFormat.Raw)
                    .hex()
                )
                controls.append(("wrong-root", bad_root, "trust-unverified", "trust"))
                for label, field, verdict in (
                    ("bad-approval-signature", "approval", "approval-not-attributable"),
                    ("bad-passkey-signature", "owner_assertion", "approval-not-attributable"),
                ):
                    altered = copy.deepcopy(document)
                    request = altered["store"]["entries"][record["references"][0]["id"]]["request"]
                    request[field]["signature"] = "00" * 64 if field == "approval" else "AA"
                    altered["record"]["references"][0]["digest"] = module._jcs_sha256(request)
                    phase = "approval" if field == "approval" else "passkey"
                    controls.append((label, altered, verdict, phase))
            row["negative_controls"] = []
            for label, altered, verdict, phase in controls:
                result = run_probe(args.go, probe_dir, work, environment, altered)
                if result["verdict"] != verdict or result.get("rejected_at") != phase:
                    raise ValueError(f"negative control {label} returned {result}")
                row["negative_controls"].append({"name": label, "result": result})
            if entry is None or entry.get("receipt") is None:
                row["comparison"] = "outside-full-history-cli-contract"
                row["reason"] = (
                    "unresolved reference" if entry is None else "no signed execution receipt"
                )
                rows.append(row)
                continue
            # Authenticate the caller-supplied trust before passing its payload
            # to the stateless CLI. This precondition uses the Python oracle.
            if not module._signed_by(store["signed_trust"], "witness-trust/1", module.ROOT_KEY):
                raise ValueError("fixture trust signature failed")
            checkpoint = entry["checkpoint"]
            epoch = checkpoint["payload"]["observed_at"]
            documents = {
                "trust.json": store["signed_trust"]["payload"],
                "checkpoint.json": checkpoint,
                "package.json": {
                    "version": "openproof-witness/1",
                    "requests": [entry["request"]],
                    "receipts": [entry["receipt"]],
                    "checkpoint": checkpoint,
                },
            }
            for filename, document in documents.items():
                (work / filename).write_text(json.dumps(document), encoding="utf-8")
            result = command(
                [
                    str(binary),
                    "verify",
                    "trust.json",
                    "checkpoint.json",
                    "package.json",
                    str(epoch),
                ],
                work,
            )
            if result.returncode == 0:
                native = json.loads(result.stdout)
                if native.get("status") != "receiver_confirmed_and_witnessed":
                    raise ValueError(f"unexpected upstream verdict: {native}")
            elif result.returncode == 1 and result.stderr.strip() == "verification_failed":
                native = {"status": "verification_failed"}
            else:
                raise RuntimeError(f"verifier execution failed: {result}")
            agreed = (result.returncode == 0) == (
                python["verdict"] == "approval-confirmed-and-executed"
            )
            row.update(
                go=native, comparison="agree" if agreed else "disagree", evaluation_epoch=epoch
            )
            rows.append(row)
        report = {
            "upstream_revision": UPSTREAM,
            "fixture_revision": FIXTURE_REVISION,
            "go_version": command([args.go, "version"], go_dir).stdout.strip(),
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "adapter_sha256": hashlib.sha256(shim.read_bytes()).hexdigest(),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "input_sha256": hashes,
            "upstream_tests": tests.stdout,
            "cases": rows,
            "limits": [
                "Historical replay at checkpoint time; current freshness is not evaluated.",
                "Two history comparisons; three cases have no comparable CLI verdict.",
                "All five have adapter results; reference lookup/digest composition is new code.",
                "Approval-only checks call native verifyAssertion without inventing a sequence.",
                "JSON serialization covers only the asserted ASCII/safe-integer fixture domain.",
                "Trust and checkpoint are supplied by this synthetic fixture harness.",
                "Go and Python share project authorship; no authorship independence is claimed.",
                "Shared rejection does not establish identical rejection reasons.",
            ],
        }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return int(any(row["comparison"] == "disagree" or not row["adapter_agrees"] for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
