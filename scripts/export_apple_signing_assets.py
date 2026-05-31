#!/usr/bin/env python3
"""
Export Apple development signing assets from Windows.

This creates a fresh local private key and CSR, submits only the CSR to Apple,
downloads a wildcard provisioning profile, and writes the resulting .p12 and
.mobileprovision files locally. The private key is never sent to Apple or to an
anisette server.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import re
import sys
import uuid
from pathlib import Path
from typing import Any

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID
except ImportError as exc:
    if __name__ == "__main__" and not any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        print(
            f"Missing dependency: {exc.name}\n"
            "Install with:\n"
            "  python -m pip install -r scripts/register_apple_device_requirements.txt",
            file=sys.stderr,
        )
        raise SystemExit(2)
    raise

import register_apple_device as device_flow

from register_apple_device import (
    DEFAULT_ANISETTE_URL,
    AppleDeveloperClient,
    AppleDeveloperServiceError,
    AnisetteClient,
    AuthenticationRejectedError,
    DebugPrinter,
    FlowError,
    SessionStore,
    VerificationCodeProvider,
    choose_team,
    configure_tls,
    default_cache_dir,
    ensure_apple_tls_or_prompt,
    find_device,
    format_request_exception,
    normalize_udid,
    password_debug_summary,
    require_field,
    resolve_password,
    retry_env_password_interactively,
    validate_https_url,
)


DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "signing-export"
DEFAULT_BUNDLE_IDENTIFIER = "*"
DEFAULT_APP_ID_NAME = "SideStore Wildcard"
DEFAULT_MACHINE_NAME = "SideStore Windows Export"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create and export a fresh Apple development .p12 plus provisioning profile."
    )
    parser.add_argument("--apple-id", help="Apple ID email.")
    parser.add_argument("--password-env", help="Read Apple ID password from this environment variable.")
    parser.add_argument("--password-stdin", action="store_true", help="Read Apple ID password from stdin.")
    parser.add_argument("--2fa-code", dest="two_factor_code", help="Verification code to use once.")
    parser.add_argument("--2fa-env", dest="two_factor_env", help="Read verification code from this environment variable.")
    parser.add_argument("--2fa-stdin", dest="two_factor_stdin", action="store_true", help="Read verification code from stdin when prompted.")
    parser.add_argument("--team-id", help="Apple developer team ID. Omit to auto-select or prompt.")
    parser.add_argument("--bundle-id", default=DEFAULT_BUNDLE_IDENTIFIER, help="App ID bundle identifier for the profile. Default: wildcard '*'.")
    parser.add_argument("--app-id-name", default=DEFAULT_APP_ID_NAME, help="Name used if a new App ID must be created.")
    parser.add_argument("--machine-name", default=DEFAULT_MACHINE_NAME, help="Machine name Apple stores on the new certificate.")
    parser.add_argument("--p12-password", default="", help="Password for the exported .p12. Default: blank.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for exported signing files.")
    parser.add_argument("--udid", help="Optional device UDID to ensure is registered before downloading the profile.")
    parser.add_argument("--device-name", help="Device name to send when registering --udid.")
    parser.add_argument("--save-pem", action="store_true", help="Also write certificate.pem and private_key.pem. These are sensitive.")
    parser.add_argument("--anisette-url", default=DEFAULT_ANISETTE_URL, help="SideStore anisette server URL.")
    parser.add_argument(
        "--anisette-mode",
        choices=["auto", "v3", "v1"],
        default="auto",
        help="Anisette protocol mode. auto tries V3 and falls back to V1 if provisioning fails.",
    )
    parser.add_argument("--allow-insecure-anisette-http", action="store_true", help="Allow http:// anisette URLs for local testing only.")
    parser.add_argument(
        "--tls-trust-store",
        choices=["auto", "system", "certifi"],
        default="auto",
        help="TLS certificate trust source. auto uses the Windows/system store on Windows.",
    )
    parser.add_argument("--ca-bundle", help="Custom CA bundle PEM file for Apple and anisette HTTPS requests.")
    parser.add_argument("--allow-insecure-tls", action="store_true", help="Disable HTTPS certificate verification. Temporary debugging only.")
    parser.add_argument(
        "--cache",
        default=str(default_cache_dir() / "anisette.json"),
        help="Path for local anisette provisioning cache.",
    )
    parser.add_argument("--reset-anisette-cache", action="store_true", help="Delete and recreate anisette cache.")
    parser.add_argument(
        "--session-cache",
        default=str(default_cache_dir() / "apple_sessions.json"),
        help="Path for cached Apple developer login tokens.",
    )
    parser.add_argument("--reset-session-cache", action="store_true", help="Delete the cached Apple session for this Apple ID before running.")
    parser.add_argument("--no-session-cache", action="store_true", help="Do not read or save cached Apple developer login tokens.")
    parser.set_defaults(debug=False)
    parser.add_argument("--debug", dest="debug", action="store_true", help="Print verbose debug logs. Secrets are redacted by default.")
    parser.add_argument("--quiet", dest="debug", action="store_false", help="Disable debug logs. This is the default.")
    parser.add_argument(
        "--unsafe-debug-secrets",
        action="store_true",
        help="Print passwords/tokens/anisette secrets in debug logs. Use only on a private machine.",
    )
    return parser


def require_interactive(parser: argparse.ArgumentParser, label: str) -> None:
    if not sys.stdin.isatty():
        parser.error(f"{label} is required in non-interactive mode.")


def validate_arguments(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.password_env and args.password_stdin:
        parser.error("Use only one of --password-env or --password-stdin.")
    if args.allow_insecure_tls and args.ca_bundle:
        parser.error("Use only one of --allow-insecure-tls or --ca-bundle.")

    two_factor_sources = sum(bool(value) for value in (args.two_factor_code, args.two_factor_env, args.two_factor_stdin))
    if two_factor_sources > 1:
        parser.error("Use only one of --2fa-code, --2fa-env, or --2fa-stdin.")

    if not args.apple_id:
        require_interactive(parser, "--apple-id")
        args.apple_id = input("Apple ID email: ").strip()

    args.bundle_id = args.bundle_id.strip()
    if not args.bundle_id:
        parser.error("--bundle-id must not be empty.")

    if args.udid:
        args.udid = normalize_udid(args.udid)

    validate_https_url(args.anisette_url, allow_http=args.allow_insecure_anisette_http)


def authenticate(args: argparse.Namespace, parser: argparse.ArgumentParser):
    debug = DebugPrinter(enabled=args.debug, unsafe_secrets=args.unsafe_debug_secrets)
    verify = configure_tls(args.tls_trust_store, args.ca_bundle, args.allow_insecure_tls, debug)
    verify = ensure_apple_tls_or_prompt(verify, debug)

    cache_path = Path(args.cache)
    session_store = None if args.no_session_cache else SessionStore(Path(args.session_cache), debug)
    if args.reset_session_cache and session_store is not None:
        session_store.delete(args.apple_id)

    verification_prompt = VerificationCodeProvider(
        args.two_factor_code,
        args.two_factor_env,
        args.two_factor_stdin,
    )

    debug("Anisette URL", args.anisette_url)
    debug("Anisette mode", args.anisette_mode)
    debug("Anisette cache path", str(cache_path))
    if session_store is not None:
        debug("Apple session cache path", str(session_store.path))

    anisette_client = AnisetteClient(args.anisette_url, cache_path, debug, verify=verify, mode=args.anisette_mode)
    anisette = anisette_client.load_or_create(reset=args.reset_anisette_cache)
    debug("Resolved anisette data", anisette.__dict__, secret=True)

    client = AppleDeveloperClient(anisette, debug, verify=verify)
    client.set_anisette_refresh(lambda: anisette_client.load_or_create(reset=False))

    account: dict[str, Any] | None = None
    session = None
    used_cached_session = False
    if session_store is not None:
        cached_session = session_store.load(args.apple_id, client.anisette)
        if cached_session is not None:
            debug("Trying cached Apple developer session")
            try:
                account = client.fetch_account(cached_session)
                session = cached_session
                session_store.save(args.apple_id, session)
                used_cached_session = True
            except FlowError as exc:
                debug("Cached Apple developer session failed; full authentication required", str(exc))
                session_store.delete(args.apple_id)

    if account is None or session is None:
        resolve_password(args, parser)
        debug("Password debug", password_debug_summary(args), secret=True)
        try:
            account, session = client.authenticate(args.apple_id, args.password, verification_prompt)
        except AuthenticationRejectedError:
            if not retry_env_password_interactively(args, debug):
                raise
            account, session = client.authenticate(args.apple_id, args.password, verification_prompt)
        if session_store is not None:
            session_store.save(args.apple_id, session)

    print()
    print(f"Authenticated as: {account.get('email', args.apple_id)}")
    if used_cached_session:
        print("Used cached Apple session; password and 2FA were not required.")

    teams = client.fetch_teams(account, session)
    team = choose_team(teams, args.team_id)
    team_id = require_field(team, "teamId", str, "Apple team selection")
    print(f"Using team: {team.get('name')} ({team_id})")

    return client, session, team_id


def generate_certificate_request():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Los Angeles"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AltSign"),
            x509.NameAttribute(NameOID.COMMON_NAME, "AltSign"),
        ]
    )
    request = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    csr_pem = request.public_bytes(serialization.Encoding.PEM)
    private_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return private_key, csr_pem, private_key_pem


def certificate_bytes_from_response(certificate_response: dict[str, Any]) -> bytes:
    attributes = certificate_response.get("attributes")
    if isinstance(attributes, dict):
        certificate_response = attributes

    cert_content = certificate_response.get("certContent")
    if isinstance(cert_content, bytes):
        return cert_content
    if isinstance(cert_content, str):
        return base64.b64decode(cert_content)

    certificate_content = certificate_response.get("certificateContent")
    if isinstance(certificate_content, str):
        return base64.b64decode(certificate_content)
    if isinstance(certificate_content, bytes):
        return certificate_content

    raise FlowError("Apple did not return certificate content.")


def load_certificate(certificate_data: bytes) -> x509.Certificate:
    stripped = certificate_data.lstrip()
    if stripped.startswith(b"-----BEGIN CERTIFICATE-----"):
        return x509.load_pem_x509_certificate(certificate_data)
    return x509.load_der_x509_certificate(certificate_data)


def create_development_certificate(client: AppleDeveloperClient, team_id: str, session, machine_name: str):
    private_key, csr_pem, private_key_pem = generate_certificate_request()
    response = client._send_developer_request(
        "ios/submitDevelopmentCSR.action",
        team_id=team_id,
        session=session,
        additional_parameters={
            "csrContent": csr_pem.decode("utf-8"),
            "machineId": str(uuid.uuid4()).upper(),
            "machineName": machine_name,
        },
    )
    certificate_response = response.get("certRequest")
    if not isinstance(certificate_response, dict):
        raise FlowError("Apple did not return the new certificate.")
    certificate_data = certificate_bytes_from_response(certificate_response)
    certificate = load_certificate(certificate_data)
    return private_key, private_key_pem, certificate, certificate_data, certificate_response


def sanitized_app_id_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9 ]+", "", name)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized or "App"


def fetch_app_ids(client: AppleDeveloperClient, team_id: str, session) -> list[dict[str, Any]]:
    response = client._send_developer_request("ios/listAppIds.action", team_id=team_id, session=session)
    app_ids = response.get("appIds")
    if not isinstance(app_ids, list):
        raise FlowError("Apple did not return App IDs.")
    return [app_id for app_id in app_ids if isinstance(app_id, dict)]


def find_or_create_app_id(client: AppleDeveloperClient, team_id: str, session, bundle_id: str, name: str) -> dict[str, Any]:
    app_ids = fetch_app_ids(client, team_id, session)
    for app_id in app_ids:
        if str(app_id.get("identifier", "")).lower() == bundle_id.lower():
            print(f"Using existing App ID: {app_id.get('name')} ({bundle_id})")
            return app_id

    print(f"Creating App ID: {bundle_id}")
    try:
        response = client._send_developer_request(
            "ios/addAppId.action",
            team_id=team_id,
            session=session,
            additional_parameters={
                "identifier": bundle_id,
                "name": sanitized_app_id_name(name),
            },
        )
    except AppleDeveloperServiceError as exc:
        if exc.result_code == 9401:
            for app_id in fetch_app_ids(client, team_id, session):
                if str(app_id.get("identifier", "")).lower() == bundle_id.lower():
                    print(f"Apple reported the App ID already exists; using: {bundle_id}")
                    return app_id
        raise

    app_id = response.get("appId")
    if not isinstance(app_id, dict):
        raise FlowError("Apple did not return the new App ID.")
    return app_id


def download_provisioning_profile(client: AppleDeveloperClient, team_id: str, session, app_id: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    app_id_id = require_field(app_id, "appIdId", str, "Apple App ID")
    response = client._send_developer_request(
        "ios/downloadTeamProvisioningProfile.action",
        team_id=team_id,
        session=session,
        additional_parameters={
            "appIdId": app_id_id,
            "DTDK_Platform": "ios",
        },
    )
    profile = response.get("provisioningProfile")
    if not isinstance(profile, dict):
        raise FlowError("Apple did not return a provisioning profile.")
    encoded_profile = profile.get("encodedProfile")
    if isinstance(encoded_profile, bytes):
        return encoded_profile, profile
    if isinstance(encoded_profile, str):
        return base64.b64decode(encoded_profile), profile
    raise FlowError("Apple returned a provisioning profile without encodedProfile data.")


def ensure_device_registered(client: AppleDeveloperClient, team_id: str, session, udid: str, device_name: str | None) -> None:
    devices = client.fetch_devices(team_id, session)
    if find_device(devices, udid) is not None:
        print(f"Device already registered: {udid}")
        return

    name = device_name or udid
    print(f"Registering device: {name} ({udid})")
    client.add_device(team_id, udid, name, session)


def serialize_p12(private_key, certificate: x509.Certificate, password: str) -> bytes:
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(
        name=b"SideStore",
        key=private_key,
        cert=certificate,
        cas=None,
        encryption_algorithm=encryption,
    )


def write_outputs(
    output_dir: Path,
    p12_data: bytes,
    profile_data: bytes,
    certificate_pem: bytes,
    private_key_pem: bytes,
    *,
    save_pem: bool,
    p12_password: str,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    p12_path = output_dir / "SideStoreSigningCertificate.p12"
    profile_path = output_dir / "SideStoreWildcard.mobileprovision"
    readme_path = output_dir / "README.txt"

    p12_path.write_bytes(p12_data)
    profile_path.write_bytes(profile_data)
    readme_path.write_text(
        "\n".join(
            [
                "SideStore signing export",
                "",
                f"Generated at: {dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
                f"SideStoreSigningCertificate.p12 password: {'provided by --p12-password' if p12_password else 'leave blank'}",
                "SideStoreWildcard.mobileprovision password: none",
                "",
            ]
        ),
        encoding="utf-8",
    )

    if save_pem:
        (output_dir / "certificate.pem").write_bytes(certificate_pem)
        (output_dir / "private_key.pem").write_bytes(private_key_pem)

    print()
    print("Exported signing assets:")
    print(f"  P12: {p12_path}")
    print(f"  Profile: {profile_path}")
    print(f"  Notes: {readme_path}")
    if save_pem:
        print(f"  Certificate PEM: {output_dir / 'certificate.pem'}")
        print(f"  Private key PEM: {output_dir / 'private_key.pem'}")


def main() -> int:
    parser = build_arg_parser()
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        parser.parse_args()
        return 0

    if sys.version_info < (3, 10):
        print("Python 3.10 or newer is required.", file=sys.stderr)
        return 2

    if (
        device_flow.requests is None
        or device_flow.truststore is None
        or device_flow.websocket is None
        or device_flow.Cipher is None
        or device_flow.algorithms is None
        or device_flow.modes is None
        or device_flow.AESGCM is None
        or device_flow.PKCS7 is None
    ):
        print(
            "Missing runtime dependencies.\n"
            "Install with:\n"
            "  python -m pip install -r scripts/register_apple_device_requirements.txt",
            file=sys.stderr,
        )
        return 2

    args = parser.parse_args()
    validate_arguments(args, parser)

    client, session, team_id = authenticate(args, parser)

    if args.udid:
        ensure_device_registered(client, team_id, session, args.udid, args.device_name)

    print()
    print("Creating a new Apple development certificate...")
    private_key, private_key_pem, certificate, certificate_data, certificate_response = create_development_certificate(
        client,
        team_id,
        session,
        args.machine_name,
    )
    serial_number = format(certificate.serial_number, "X").lstrip("0")
    print(f"Created certificate serial: {serial_number}")

    app_id = find_or_create_app_id(client, team_id, session, args.bundle_id, args.app_id_name)
    profile_data, profile = download_provisioning_profile(client, team_id, session, app_id)
    print(f"Downloaded profile: {profile.get('name') or profile.get('provisioningProfileId') or args.bundle_id}")

    p12_data = serialize_p12(private_key, certificate, args.p12_password)
    write_outputs(
        Path(args.output_dir),
        p12_data,
        profile_data,
        certificate.public_bytes(serialization.Encoding.PEM),
        private_key_pem,
        save_pem=args.save_pem,
        p12_password=args.p12_password,
    )

    if certificate_response.get("machineId"):
        print(f"Apple machine ID: {certificate_response.get('machineId')}")
    print("Done.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        raise SystemExit(130)
    except AppleDeveloperServiceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except FlowError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        if hasattr(exc, "request"):
            print(f"ERROR: {format_request_exception(exc)}", file=sys.stderr)
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
