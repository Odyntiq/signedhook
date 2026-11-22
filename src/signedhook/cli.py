"""Command-line interface: inspect providers, sign payloads, verify requests.

Exit codes: ``0`` verified/ok, ``1`` verification failed (reason code
reported), ``2`` usage or configuration error. Secrets are accepted as
options (never echoed back) and header/payload content is never printed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from ._errors import ConfigurationError, SignedhookError, UnknownProviderError
from ._providers import list_providers
from ._settings import Settings
from .signing import sign
from .verify import UNSET, verify

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="signedhook",
        description="Verify signed webhooks from any provider with one call.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    providers = sub.add_parser("providers", help="list registered provider schemes")
    providers.add_argument("--json", action="store_true", help="output JSON")

    sign_parser = sub.add_parser("sign", help="produce Standard Webhooks headers")
    sign_parser.add_argument("--secret", required=True, help="signing secret (whsec_... or raw)")
    sign_parser.add_argument("--id", required=True, dest="webhook_id", help="unique webhook id")
    sign_parser.add_argument("--ts", type=int, default=None, help="timestamp override")
    sign_parser.add_argument("--payload-file", default=None, help="read payload from file")
    sign_parser.add_argument("--json", action="store_true", help="output JSON")

    verify_parser = sub.add_parser("verify", help="verify a webhook request")
    verify_parser.add_argument("--provider", default="auto", help="provider name or 'auto'")
    verify_parser.add_argument(
        "--secret",
        required=True,
        action="append",
        dest="secrets",
        metavar="SECRET",
        help="signing secret; repeat for rotation",
    )
    verify_parser.add_argument(
        "--tolerance",
        type=int,
        default=None,
        help=f"tolerance seconds (default: {Settings().tolerance_seconds})",
    )
    verify_parser.add_argument(
        "--no-tolerance", action="store_true", help="disable the timestamp check"
    )
    verify_parser.add_argument("--now", type=int, default=None, help="current time override")
    verify_parser.add_argument(
        "--header",
        action="append",
        dest="headers",
        default=[],
        metavar='"Name: value"',
        help="request header; repeatable",
    )
    verify_parser.add_argument("--payload-file", default=None, help="read payload from file")
    verify_parser.add_argument("--json", action="store_true", help="output JSON")
    return parser


def _read_payload(path: str | None) -> bytes:
    if path is None:
        return sys.stdin.buffer.read()
    with open(path, "rb") as handle:
        return handle.read()


def _parse_headers(raw: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw:
        name, sep, value = item.partition(":")
        if not sep:
            raise ConfigurationError(f"--header expects 'Name: value', got {name!r}")
        headers[name.strip().lower()] = value.strip()
    return headers


def _cmd_providers(args: argparse.Namespace) -> int:
    from ._providers import get_provider

    names = list_providers()
    if args.json:
        payload = [
            {
                "name": name,
                "scheme": get_provider(name).scheme,
                "required_headers": list(get_provider(name).required_headers),
            }
            for name in names
        ]
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for name in names:
            provider = get_provider(name)
            headers = ", ".join(provider.required_headers)
            sys.stdout.write(f"{name:10} {provider.scheme:12} {headers}\n")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    payload = _read_payload(args.payload_file)
    headers = sign(payload, secret=args.secret, webhook_id=args.webhook_id, now=args.ts)
    if args.json:
        json.dump(headers, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for name, value in headers.items():
            sys.stdout.write(f"{name}: {value}\n")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    payload = _read_payload(args.payload_file)
    headers = _parse_headers(args.headers)
    tolerance: int | None | object = UNSET
    if args.no_tolerance:
        tolerance = None
    elif args.tolerance is not None:
        tolerance = args.tolerance
    try:
        result = verify(
            payload,
            headers,
            secrets=args.secrets,
            provider=args.provider,
            tolerance=tolerance,  # type: ignore[arg-type]
            now=args.now,
            settings=Settings.from_env(),
        )
    except (UnknownProviderError, ConfigurationError):
        # Usage/config errors are process errors, not verification failures.
        raise
    except SignedhookError as error:
        if args.json:
            json.dump(
                {"ok": False, "code": error.code, "message": str(error)},
                sys.stdout,
                indent=2,
            )
            sys.stdout.write("\n")
        else:
            sys.stdout.write(f"FAILED [{error.code}] {error}\n")
        return 1
    if args.json:
        json.dump(
            {
                "ok": True,
                "provider": result.provider,
                "scheme": result.scheme,
                "timestamp": result.timestamp,
                "matched_secret_index": result.matched_secret_index,
                "message_key": result.message_key,
                "payload_size": result.payload_size,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            f"OK provider={result.provider} scheme={result.scheme} "
            f"secret_index={result.matched_secret_index}\n"
        )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "providers":
            return _cmd_providers(args)
        if args.command == "sign":
            return _cmd_sign(args)
        if args.command == "verify":
            return _cmd_verify(args)
    except (SignedhookError, OSError) as error:
        sys.stderr.write(f"error: {error}\n")
        return 2
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
