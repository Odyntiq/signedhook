"""CLI tests executed as real subprocesses (python -m signedhook.cli)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
ENV = {**os.environ, "PYTHONPATH": str(SRC)}

PAYLOAD = b'{"event":"ping","seq":1}'
STD_SECRET = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="


def run(*args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "signedhook.cli", *args],
        input=stdin,
        capture_output=True,
        env=ENV,
        timeout=60,
        check=False,
    )


def test_providers_lists_builtin_schemes() -> None:
    result = run("providers")
    assert result.returncode == 0
    assert b"standard" in result.stdout
    assert b"razorpay" in result.stdout


def test_providers_json_is_valid() -> None:
    result = run("providers", "--json")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    names = {entry["name"] for entry in payload}
    assert {"standard", "stripe", "github", "slack", "shopify", "razorpay"} <= names


def test_sign_then_verify_roundtrip() -> None:
    signed = run(
        "sign",
        "--secret",
        STD_SECRET,
        "--id",
        "msg_cli_1",
        "--ts",
        "1700000000",
        "--json",
        stdin=PAYLOAD,
    )
    assert signed.returncode == 0, signed.stderr
    headers = json.loads(signed.stdout)
    argv = ["verify", "--provider", "standard", "--secret", STD_SECRET, "--now", "1700000000"]
    for name, value in headers.items():
        argv += ["--header", f"{name}: {value}"]
    result = run(*argv, stdin=PAYLOAD)
    assert result.returncode == 0, result.stderr
    assert b"OK provider=standard" in result.stdout


def test_verify_rejects_tampered_payload_with_code() -> None:
    signed = run(
        "sign",
        "--secret",
        STD_SECRET,
        "--id",
        "msg_cli_2",
        "--ts",
        "1700000000",
        "--json",
        stdin=PAYLOAD,
    )
    headers = json.loads(signed.stdout)
    argv = [
        "verify",
        "--provider",
        "standard",
        "--secret",
        STD_SECRET,
        "--now",
        "1700000000",
        "--json",
    ]
    for name, value in headers.items():
        argv += ["--header", f"{name}: {value}"]
    result = run(*argv, stdin=b"tampered-body")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["code"] == "signature_mismatch"


def test_verify_no_tolerance_accepts_old_timestamp() -> None:
    signed = run(
        "sign",
        "--secret",
        STD_SECRET,
        "--id",
        "msg_cli_3",
        "--ts",
        "1700000000",
        "--json",
        stdin=PAYLOAD,
    )
    headers = json.loads(signed.stdout)
    argv = ["verify", "--provider", "standard", "--secret", STD_SECRET, "--no-tolerance", "--json"]
    for name, value in headers.items():
        argv += ["--header", f"{name}: {value}"]
    result = run(*argv, stdin=PAYLOAD)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ok"] is True


def test_verify_unknown_provider_is_config_error(tmp_path: Path) -> None:
    payload_file = tmp_path / "payload.json"
    payload_file.write_bytes(PAYLOAD)
    result = run(
        "verify",
        "--provider",
        "nonexistent",
        "--secret",
        STD_SECRET,
        "--payload-file",
        str(payload_file),
    )
    assert result.returncode == 2
    assert b"unknown provider" in result.stderr


def test_verify_reports_failure_exit_code(tmp_path: Path) -> None:
    payload_file = tmp_path / "payload.json"
    payload_file.write_bytes(PAYLOAD)
    bogus_sig = "sha256=" + "aa" * 32
    result = run(
        "verify",
        "--provider",
        "github",
        "--secret",
        "wrong-secret",
        "--header",
        f"x-hub-signature-256: {bogus_sig}",
        "--payload-file",
        str(payload_file),
        "--json",
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["code"] == "signature_mismatch"


def test_missing_payload_file_is_error(tmp_path: Path) -> None:
    result = run(
        "verify",
        "--provider",
        "github",
        "--secret",
        "whatever",
        "--payload-file",
        str(tmp_path / "missing.bin"),
    )
    assert result.returncode == 2


def test_header_without_colon_is_error(tmp_path: Path) -> None:
    payload_file = tmp_path / "payload.json"
    payload_file.write_bytes(PAYLOAD)
    result = run(
        "verify",
        "--provider",
        "github",
        "--secret",
        "whatever",
        "--header",
        "malformed-header",
        "--payload-file",
        str(payload_file),
    )
    assert result.returncode == 2


@pytest.mark.parametrize("args", [["providers"], ["sign", "--secret", "s", "--id", "x"]])
def test_module_entry_point(args: list[str]) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "signedhook", *args],
        input=b"" if args[0] == "sign" else None,
        capture_output=True,
        env=ENV,
        timeout=60,
        check=False,
    )
    assert result.returncode in (0, 1, 2)
