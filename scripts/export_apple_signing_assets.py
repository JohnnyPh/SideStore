#!/usr/bin/env python3
"""
Export Apple signing assets from Windows.

This creates or reuses a local private key and certificate, downloads wildcard
provisioning profiles, and writes the resulting .p12 and .mobileprovision files
locally. The private key is never sent to Apple or to an anisette server.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import sys
import uuid
from pathlib import Path
from urllib.parse import urlencode
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
PRIMARY_P12_FILENAME = "Certificate.p12"
P12_INPUT_FILENAMES = [PRIMARY_P12_FILENAME, "SideStoreSigningCertificate.p12"]
SERVICES_BASE_URL = "https://developerservices2.apple.com/services/v1/"
DEFAULT_CERTIFICATE_TYPE = "auto"
CERTIFICATE_CONFIGS = {
    "development": {
        "display_name": "iOS Development",
        "filter_type": "IOS_DEVELOPMENT",
        "submit_action": "ios/submitDevelopmentCSR.action",
        "aps_environment": "development",
        "get_task_allow": True,
    },
    "distribution": {
        "display_name": "iOS Distribution",
        "filter_type": "IOS_DISTRIBUTION",
        "submit_action": "ios/submitDistributionCSR.action",
        "aps_environment": "production",
        "get_task_allow": False,
    },
}
NETWORK_EXTENSION_PROVIDERS = [
    "app-proxy-provider",
    "content-filter-provider",
    "packet-tunnel-provider",
    "dns-proxy",
    "dns-settings",
    "relay",
    "url-filter-provider",
    "hotspot-provider",
]
PROFILE_PLATFORM_CONFIGS = {
    "ios": {
        "display_name": "iOS/iPadOS",
        "filename": "Wildcard.mobileprovision",
        "device_classes": {"iphone", "ipad", "ipod", "ipodtouch"},
        "parameter_attempts": [{"DTDK_Platform": "ios"}],
    },
    "tvos": {
        "display_name": "tvOS",
        "filename": "Wildcard-tvOS.mobileprovision",
        "device_classes": {"tvos", "appletv", "appletvdevice"},
        "parameter_attempts": [{"DTDK_Platform": "tvos", "subPlatform": "tvOS"}],
    },
    "visionos": {
        "display_name": "visionOS",
        "filename": "Wildcard-visionOS.mobileprovision",
        "device_classes": {"vision", "visionos", "xros", "realitydevice"},
        "parameter_attempts": [
            {"DTDK_Platform": "xros", "subPlatform": "xrOS"},
            {"DTDK_Platform": "visionos", "subPlatform": "visionOS"},
        ],
    },
}
DEFAULT_PROFILE_PLATFORMS = "ios"
PROFILE_PLATFORM_ALIASES = {
    "ipados": "ios",
    "xros": "visionos",
}
MAXIMUM_CAPABILITIES = [
    "INCREASED_MEMORY_LIMIT",
    "INCREASED_MEMORY_LIMIT_DEBUGGING",
    "EXTENDED_VIRTUAL_ADDRESSING",
]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or reuse Apple signing assets and export a .p12 plus provisioning profiles."
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
    parser.add_argument(
        "--certificate-type",
        choices=["auto", *sorted(CERTIFICATE_CONFIGS)],
        default=DEFAULT_CERTIFICATE_TYPE,
        help=(
            "Certificate type to create. auto tries distribution first and falls back to development "
            f"when Apple reports the team is not eligible for distribution. Default: {DEFAULT_CERTIFICATE_TYPE}."
        ),
    )
    parser.add_argument(
        "--skip-max-entitlements",
        action="store_true",
        help="Do not ask Apple to update the wildcard App ID with maximum entitlements before downloading the profile.",
    )
    parser.add_argument(
        "--replace-existing-wildcard-app-id",
        action="store_true",
        help=(
            "Delete the existing '*' App ID if it is not named --app-id-name, then create a new preferred wildcard App ID. "
            "This can invalidate profiles that used the old wildcard App ID."
        ),
    )
    parser.add_argument(
        "--allow-revoke-existing-certificate",
        action="store_true",
        help="If Apple refuses a new certificate because one already exists, revoke matching existing certificates and retry.",
    )
    parser.add_argument(
        "--force-new-certificate",
        action="store_true",
        help="Ignore a reusable local P12 in --output-dir and create a new Apple certificate.",
    )
    parser.add_argument("--p12-password", default="", help="Password for the exported .p12. Default: blank.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for exported signing files.")
    parser.add_argument(
        "--profile-platforms",
        default=DEFAULT_PROFILE_PLATFORMS,
        help=(
            "Comma-separated provisioning profile platforms to export: auto, all, ios, ipados, tvos, visionos, xros. "
            f"Default: {DEFAULT_PROFILE_PLATFORMS}."
        ),
    )
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


def parse_profile_platforms(value: str, parser: argparse.ArgumentParser) -> list[str] | str:
    platforms = [
        PROFILE_PLATFORM_ALIASES.get(platform.strip().lower(), platform.strip().lower())
        for platform in value.split(",")
        if platform.strip()
    ]
    if not platforms:
        parser.error("--profile-platforms must not be empty.")
    if "auto" in platforms:
        if len(platforms) > 1:
            parser.error("Use --profile-platforms auto by itself.")
        return "auto"
    if "all" in platforms:
        if len(platforms) > 1:
            parser.error("Use --profile-platforms all by itself.")
        return list(PROFILE_PLATFORM_CONFIGS)

    unknown = [platform for platform in platforms if platform not in PROFILE_PLATFORM_CONFIGS]
    if unknown:
        parser.error(f"Unknown --profile-platforms value: {', '.join(unknown)}.")

    deduplicated: list[str] = []
    for platform in platforms:
        if platform not in deduplicated:
            deduplicated.append(platform)
    return deduplicated


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

    args.profile_platforms = parse_profile_platforms(args.profile_platforms, parser)

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

    return client, session, team


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


def services_headers(client: AppleDeveloperClient, session, method: str) -> dict[str, str]:
    headers = client.anisette.developer_headers(session.dsid, session.auth_token)
    headers.update(
        {
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
            "X-HTTP-Method-Override": method,
        }
    )
    return headers


def send_services_request(
    client: AppleDeveloperClient,
    path: str,
    *,
    session,
    team_id: str,
    method: str = "GET",
    additional_parameters: dict[str, str] | None = None,
) -> dict[str, Any]:
    parameters = {"teamId": team_id}
    if additional_parameters:
        parameters.update(additional_parameters)

    body = json.dumps({"urlEncodedQueryParams": urlencode(parameters)}).encode("utf-8")
    url = f"{SERVICES_BASE_URL}{path.lstrip('/')}"
    headers = services_headers(client, session, method)
    client.debug("Services request URL", url)
    client.debug("Services request parameters", parameters)
    client.debug("Services request headers", headers, secret=True)
    try:
        response = client.http.post(url, headers=headers, data=body, timeout=30)
    except device_flow.requests.RequestException as exc:
        raise FlowError(f"Apple developer service request failed for {path}: {format_request_exception(exc)}") from exc

    client.debug("Services response status", response.status_code)
    client.debug("Services raw response", response.content[:4000], secret=True)
    if response.content:
        try:
            payload = response.json()
        except ValueError as exc:
            raise FlowError(f"Apple developer service {path} returned invalid JSON.") from exc
        if not isinstance(payload, dict):
            raise FlowError(f"Apple developer service {path} returned an invalid JSON object.")
    else:
        payload = {}

    result_code_value = payload.get("resultCode")
    if result_code_value not in (None, 0, "0"):
        try:
            result_code = int(result_code_value)
        except (TypeError, ValueError):
            result_code = -1
        message = payload.get("userString") or payload.get("resultString") or "Unknown Apple error"
        raise AppleDeveloperServiceError(result_code, str(message), payload)

    if not response.ok:
        raise FlowError(f"Apple developer service {path} failed: HTTP {response.status_code} {response.reason}")

    return payload


def certificate_config(certificate_type: str) -> dict[str, Any]:
    return CERTIFICATE_CONFIGS[certificate_type]


def certificate_display_type(certificate_type: str) -> str:
    return str(certificate_config(certificate_type)["display_name"])


def fetch_certificates(client: AppleDeveloperClient, team_id: str, session, certificate_type: str) -> list[dict[str, Any]]:
    response = send_services_request(
        client,
        "certificates",
        session=session,
        team_id=team_id,
        additional_parameters={"filter[certificateType]": str(certificate_config(certificate_type)["filter_type"])},
    )
    certificates = response.get("data")
    if not isinstance(certificates, list):
        raise FlowError(f"Apple did not return {certificate_display_type(certificate_type)} certificates.")
    return [certificate for certificate in certificates if isinstance(certificate, dict)]


def fetch_certificate(client: AppleDeveloperClient, team_id: str, session, certificate_id: str) -> dict[str, Any]:
    response = send_services_request(
        client,
        f"certificates/{certificate_id}",
        session=session,
        team_id=team_id,
    )
    certificate = response.get("data")
    if not isinstance(certificate, dict):
        raise FlowError(f"Apple did not return certificate {certificate_id}.")
    return certificate


def certificate_display_name(certificate: dict[str, Any], certificate_type: str) -> str:
    attributes = certificate.get("attributes")
    if not isinstance(attributes, dict):
        attributes = certificate

    name = attributes.get("name") or certificate_display_type(certificate_type)
    serial_number = attributes.get("serialNumber") or attributes.get("serialNum")
    machine_name = attributes.get("machineName")
    parts = [str(name)]
    if serial_number:
        parts.append(f"serial {serial_number}")
    if machine_name:
        parts.append(f"machine {machine_name}")
    if certificate.get("id"):
        parts.append(f"id {certificate['id']}")
    return ", ".join(parts)


def normalized_serial_number(value: Any) -> str:
    text = str(value or "").strip().upper()
    text = text[2:] if text.startswith("0X") else text
    text = re.sub(r"[^0-9A-F]", "", text)
    return text.lstrip("0") or "0"


def certificate_serial_number(certificate: x509.Certificate) -> str:
    return normalized_serial_number(format(certificate.serial_number, "X"))


def certificate_record_serial_number(certificate: dict[str, Any]) -> str | None:
    attributes = certificate.get("attributes")
    if not isinstance(attributes, dict):
        attributes = certificate

    for key in ("serialNumber", "serialNum"):
        value = attributes.get(key)
        if value:
            return normalized_serial_number(value)

    try:
        return certificate_serial_number(load_certificate(certificate_bytes_from_response(certificate)))
    except (FlowError, ValueError):
        return None


def certificate_expires_at(certificate: x509.Certificate) -> dt.datetime:
    expires_at = getattr(certificate, "not_valid_after_utc", None)
    if isinstance(expires_at, dt.datetime):
        return expires_at
    return certificate.not_valid_after.replace(tzinfo=dt.timezone.utc)


def serialize_private_key_pem(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def p12_candidate_paths(output_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for name in P12_INPUT_FILENAMES:
        path = output_dir / name
        if path not in paths:
            paths.append(path)
    return paths


def load_reusable_p12(output_dir: Path, password: str) -> tuple[Path, Any, bytes, x509.Certificate] | None:
    candidate_passwords: list[bytes | None]
    if password:
        candidate_passwords = [password.encode("utf-8")]
    else:
        candidate_passwords = [None, b""]

    for path in p12_candidate_paths(output_dir):
        if not path.exists():
            continue

        p12_data = path.read_bytes()
        last_error: Exception | None = None
        for candidate_password in candidate_passwords:
            try:
                private_key, certificate, _additional_certificates = pkcs12.load_key_and_certificates(
                    p12_data,
                    candidate_password,
                )
            except (TypeError, ValueError) as exc:
                last_error = exc
                continue

            if private_key is None or certificate is None:
                last_error = FlowError(f"{path.name} does not contain both a private key and certificate.")
                continue

            private_key_pem = serialize_private_key_pem(private_key)
            return path, private_key, private_key_pem, certificate

        if last_error is not None:
            print(f"Could not reuse {path.name}: {last_error}")

    return None


def find_matching_certificate_record(
    client: AppleDeveloperClient,
    team_id: str,
    session,
    certificate: x509.Certificate,
    requested_certificate_type: str,
) -> tuple[str, dict[str, Any]] | None:
    serial_number = certificate_serial_number(certificate)
    for certificate_type in certificate_type_attempts(requested_certificate_type):
        try:
            certificates = fetch_certificates(client, team_id, session, certificate_type)
        except AppleDeveloperServiceError as exc:
            if certificate_type == "distribution" and exc.result_code == 4100 and requested_certificate_type == "auto":
                continue
            raise

        for certificate_record in certificates:
            if certificate_record_serial_number(certificate_record) == serial_number:
                return certificate_type, certificate_record

    return None


def revoke_certificate(client: AppleDeveloperClient, team_id: str, session, certificate: dict[str, Any], certificate_type: str) -> None:
    certificate_id = require_field(certificate, "id", str, f"Apple {certificate_display_type(certificate_type)} certificate")
    print(f"Revoking existing certificate: {certificate_display_name(certificate, certificate_type)}")
    send_services_request(
        client,
        f"certificates/{certificate_id}",
        session=session,
        team_id=team_id,
        method="DELETE",
    )


def replace_existing_certificates(
    client: AppleDeveloperClient,
    team_id: str,
    session,
    machine_name: str,
    certificate_type: str,
):
    certificates = fetch_certificates(client, team_id, session, certificate_type)
    display_name = certificate_display_type(certificate_type)
    if not certificates:
        raise FlowError(
            f"Apple refused a new {display_name} certificate because one already exists or is pending, "
            "but the certificate list did not include a revocable certificate."
        )

    print("Apple refused a new certificate because one already exists.")
    print(f"Revoking only as many existing {display_name} certificate(s) as Apple requires.")
    for certificate in certificates:
        revoke_certificate(client, team_id, session, certificate, certificate_type)
        try:
            print(f"Retrying {display_name} certificate creation...")
            return create_certificate(client, team_id, session, machine_name, certificate_type)
        except AppleDeveloperServiceError as exc:
            if exc.result_code != 7460:
                raise
            print("Apple still reports the certificate limit; checking the next revocable certificate.")

    raise FlowError(
        f"Apple still refused a new {display_name} certificate after revoking the listed certificates. "
        "A pending certificate request may still be blocking creation."
    )


def distribution_not_eligible_error() -> FlowError:
    return FlowError(
        "Apple rejected iOS Distribution certificate creation for this team: the team is not eligible for "
        "that feature. A local script cannot turn a free Xcode provisioning membership into a distribution "
        "certificate because Apple must issue and sign that certificate."
    )


def is_xcode_free_team(team: dict[str, Any]) -> bool:
    if bool(team.get("xcodeFreeOnly")):
        return True

    memberships = team.get("memberships")
    if isinstance(memberships, list):
        for membership in memberships:
            if not isinstance(membership, dict):
                continue
            name = str(membership.get("name", "")).lower()
            product_id = str(membership.get("membershipProductId", "")).lower()
            if "free" in name or product_id == "fp22":
                return True

    member = team.get("currentTeamMember")
    if isinstance(member, dict):
        roles = member.get("roles")
        if isinstance(roles, list) and any(str(role) == "XCODE_FREE_USER" for role in roles):
            return True

    return False


def select_certificate_type(requested_certificate_type: str, team: dict[str, Any]) -> str:
    if requested_certificate_type != "auto":
        return requested_certificate_type

    if is_xcode_free_team(team):
        print("Team appears to use Xcode Free Provisioning; best available certificate type is iOS Development.")
        return "development"

    return "distribution"


def certificate_type_attempts(requested_certificate_type: str) -> list[str]:
    if requested_certificate_type == "auto":
        return ["distribution", "development"]
    return [requested_certificate_type]


def create_best_available_certificate(
    client: AppleDeveloperClient,
    team_id: str,
    session,
    machine_name: str,
    requested_certificate_type: str,
    *,
    allow_revoke_existing_certificate: bool,
):
    for certificate_type in certificate_type_attempts(requested_certificate_type):
        display_certificate_type = certificate_display_type(certificate_type)
        print()
        print(f"Creating a new Apple {display_certificate_type} certificate...")
        try:
            result = create_certificate(client, team_id, session, machine_name, certificate_type)
            return certificate_type, *result
        except AppleDeveloperServiceError as exc:
            if certificate_type == "distribution" and exc.result_code == 4100:
                if requested_certificate_type == "auto":
                    print("Apple reports this team is not eligible for iOS Distribution certificates.")
                    print("Falling back to the best available option: iOS Development.")
                    continue
                raise distribution_not_eligible_error() from exc
            if exc.result_code != 7460:
                raise
            if not allow_revoke_existing_certificate:
                raise FlowError(
                    f"Apple already has a current or pending {display_certificate_type} certificate for this team. "
                    "Apple only stores the public certificate, so this script cannot export a usable P12 "
                    "unless it creates the certificate from a local private key. Rerun with "
                    "--allow-revoke-existing-certificate to replace the existing certificate and generate a matching P12."
                ) from exc
            result = replace_existing_certificates(
                client,
                team_id,
                session,
                machine_name,
                certificate_type,
            )
            return certificate_type, *result

    raise distribution_not_eligible_error()


def get_or_create_signing_certificate(
    client: AppleDeveloperClient,
    team_id: str,
    session,
    output_dir: Path,
    machine_name: str,
    requested_certificate_type: str,
    *,
    p12_password: str,
    force_new_certificate: bool,
    allow_revoke_existing_certificate: bool,
):
    if not force_new_certificate:
        reusable = load_reusable_p12(output_dir, p12_password)
        if reusable is not None:
            p12_path, private_key, private_key_pem, certificate = reusable
            expires_at = certificate_expires_at(certificate)
            if expires_at <= dt.datetime.now(dt.timezone.utc):
                print(f"Local P12 certificate is expired, so it cannot be reused: {p12_path}")
            else:
                match = find_matching_certificate_record(
                    client,
                    team_id,
                    session,
                    certificate,
                    requested_certificate_type,
                )
                if match is not None:
                    certificate_type, certificate_record = match
                    certificate_id = require_field(
                        certificate_record,
                        "id",
                        str,
                        f"Apple {certificate_display_type(certificate_type)} certificate",
                    )
                    print()
                    print(
                        "Reusing local signing certificate: "
                        f"{p12_path.name}, serial {certificate_serial_number(certificate)}, "
                        f"expires {expires_at.date().isoformat()}"
                    )
                    return (
                        certificate_type,
                        private_key,
                        private_key_pem,
                        certificate,
                        certificate.public_bytes(serialization.Encoding.DER),
                        {"id": certificate_id, "certificateId": certificate_id},
                    )

                print(
                    "Local P12 exists but Apple no longer lists its certificate for this team, "
                    "so it cannot be used to create a matching provisioning profile."
                )

    return create_best_available_certificate(
        client,
        team_id,
        session,
        machine_name,
        requested_certificate_type,
        allow_revoke_existing_certificate=allow_revoke_existing_certificate,
    )


def create_certificate(client: AppleDeveloperClient, team_id: str, session, machine_name: str, certificate_type: str):
    private_key, csr_pem, private_key_pem = generate_certificate_request()
    response = client._send_developer_request(
        str(certificate_config(certificate_type)["submit_action"]),
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
    try:
        certificate_data = certificate_bytes_from_response(certificate_response)
    except FlowError:
        certificate_id = certificate_response.get("certificateId") or certificate_response.get("certRequestId")
        if not isinstance(certificate_id, str) or not certificate_id:
            raise
        certificate_record = fetch_certificate(client, team_id, session, certificate_id)
        certificate_data = certificate_bytes_from_response(certificate_record)
    certificate = load_certificate(certificate_data)
    return private_key, private_key_pem, certificate, certificate_data, certificate_response


def certificate_identifier_from_response(certificate_response: dict[str, Any]) -> str | None:
    for key in ("certificateId", "certRequestId", "id"):
        value = certificate_response.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def sanitized_app_id_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9 ]+", "", name)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized or "App"


def app_id_name(app_id: dict[str, Any]) -> str:
    return str(app_id.get("name") or app_id.get("appIdName") or "").strip()


def app_id_matches_bundle(app_id: dict[str, Any], bundle_id: str) -> bool:
    return str(app_id.get("identifier", "")).lower() == bundle_id.lower()


def app_id_matches_name(app_id: dict[str, Any], name: str) -> bool:
    return app_id_name(app_id).lower() == sanitized_app_id_name(name).lower()


def fetch_app_ids(client: AppleDeveloperClient, team_id: str, session) -> list[dict[str, Any]]:
    response = client._send_developer_request("ios/listAppIds.action", team_id=team_id, session=session)
    app_ids = response.get("appIds")
    if not isinstance(app_ids, list):
        raise FlowError("Apple did not return App IDs.")
    return [app_id for app_id in app_ids if isinstance(app_id, dict)]


def delete_app_id(client: AppleDeveloperClient, team_id: str, session, app_id: dict[str, Any]) -> None:
    app_id_id = require_field(app_id, "appIdId", str, "Apple App ID")
    print(f"Deleting existing App ID: {app_id_name(app_id)} ({app_id.get('identifier')})")
    client._send_developer_request(
        "ios/deleteAppId.action",
        team_id=team_id,
        session=session,
        additional_parameters={"appIdId": app_id_id},
    )


def find_or_create_app_id(
    client: AppleDeveloperClient,
    team_id: str,
    session,
    bundle_id: str,
    name: str,
    *,
    replace_existing_wildcard_app_id: bool,
) -> dict[str, Any]:
    app_ids = fetch_app_ids(client, team_id, session)
    matching_app_ids = [app_id for app_id in app_ids if app_id_matches_bundle(app_id, bundle_id)]
    for app_id in matching_app_ids:
        if app_id_matches_name(app_id, name):
            print(f"Using existing preferred App ID: {app_id_name(app_id)} ({bundle_id})")
            return app_id

    if replace_existing_wildcard_app_id:
        if bundle_id != "*":
            raise FlowError("--replace-existing-wildcard-app-id can only be used with --bundle-id '*'.")
        for app_id in matching_app_ids:
            delete_app_id(client, team_id, session, app_id)
        matching_app_ids = []

    if matching_app_ids:
        existing_names = ", ".join(app_id_name(app_id) or "(unnamed)" for app_id in matching_app_ids)
        print(
            f"Existing App ID(s) already use {bundle_id}: {existing_names}. "
            f"Asking Apple to create preferred App ID: {sanitized_app_id_name(name)}."
        )
    else:
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
        if exc.result_code in {9400, 9401} and matching_app_ids:
            fallback = matching_app_ids[0]
            print(
                "Apple did not allow a second App ID with that bundle identifier; "
                f"using existing App ID: {app_id_name(fallback)} ({bundle_id})"
            )
            return fallback
        if exc.result_code == 9401:
            for app_id in fetch_app_ids(client, team_id, session):
                if app_id_matches_bundle(app_id, bundle_id):
                    print(f"Apple reported the App ID already exists; using: {app_id_name(app_id)} ({bundle_id})")
                    return app_id
        raise

    app_id = response.get("appId")
    if not isinstance(app_id, dict):
        raise FlowError("Apple did not return the new App ID.")
    return app_id


def maximum_entitlements(
    team_id: str,
    certificate_type: str,
    *,
    include_push: bool,
    include_app_groups: bool,
    include_network_extension: bool,
    include_passbook: bool,
    include_siri: bool,
    include_icloud: bool,
    include_inter_app_audio: bool,
    include_data_protection: bool,
) -> dict[str, Any]:
    wildcard_identifier = f"{team_id}.*"
    entitlements: dict[str, Any] = {
        "application-identifier": wildcard_identifier,
        "com.apple.developer.team-identifier": team_id,
        "keychain-access-groups": [wildcard_identifier, "com.apple.token"],
        "get-task-allow": bool(certificate_config(certificate_type)["get_task_allow"]),
    }
    if include_push:
        entitlements["aps-environment"] = str(certificate_config(certificate_type)["aps_environment"])
    if include_app_groups:
        entitlements["com.apple.security.application-groups"] = [f"group.{team_id}.*"]
    if include_inter_app_audio:
        entitlements["inter-app-audio"] = True
    if include_data_protection:
        entitlements["com.apple.developer.default-data-protection"] = "NSFileProtectionComplete"
    if include_network_extension:
        entitlements["com.apple.developer.networking.networkextension"] = NETWORK_EXTENSION_PROVIDERS
    if include_passbook:
        entitlements["com.apple.developer.pass-type-identifiers"] = [wildcard_identifier]
    if include_siri:
        entitlements["com.apple.developer.siri"] = True
    if include_icloud:
        entitlements["com.apple.developer.ubiquity-container-identifiers"] = [wildcard_identifier]
        entitlements["com.apple.developer.ubiquity-kvstore-identifier"] = wildcard_identifier
    return entitlements


def maximum_feature_parameters(
    *,
    include_push: bool,
    include_app_groups: bool,
    include_network_extension: bool,
    include_passbook: bool,
    include_siri: bool,
    include_icloud: bool,
    include_inter_app_audio: bool,
    include_data_protection: bool,
) -> dict[str, Any]:
    parameters: dict[str, Any] = {}
    if include_push:
        parameters["push"] = True
    if include_app_groups:
        parameters["APG3427HIY"] = True
    if include_inter_app_audio:
        parameters["IAD53UNK2F"] = True
    if include_data_protection:
        parameters["dataProtection"] = "complete"
    if include_network_extension:
        parameters["NWEXT04537"] = True
    if include_passbook:
        parameters["passbook"] = True
    if include_siri:
        parameters["SI015DKUHP"] = True
    if include_icloud:
        parameters["iCloud"] = True
        parameters["cloudKitVersion"] = 1
    return parameters


def entitlement_attempts(certificate_type: str) -> list[dict[str, Any]]:
    broad = {
        "include_app_groups": True,
        "include_network_extension": True,
        "include_passbook": True,
        "include_siri": True,
        "include_icloud": True,
        "include_inter_app_audio": True,
        "include_data_protection": True,
    }
    return [
        {
            "label": "maximum wildcard entitlements including push notifications, app groups, NetworkExtension, iCloud, Siri, pass IDs, and inter-app audio",
            "include_push": True,
            "include_capabilities": True,
            **broad,
        },
        {
            "label": "maximum wildcard entitlements without push notifications",
            "include_push": False,
            "include_capabilities": True,
            **broad,
        },
        {
            "label": "appdb-style wildcard entitlements without kernel capability flags",
            "include_push": False,
            "include_capabilities": False,
            **broad,
        },
        {
            "label": "appdb-style wildcard entitlements without app groups",
            "include_push": False,
            "include_capabilities": False,
            **{**broad, "include_app_groups": False},
        },
        {
            "label": "wildcard entitlements without NetworkExtension",
            "include_push": False,
            "include_capabilities": False,
            **{**broad, "include_app_groups": False, "include_network_extension": False},
        },
        {
            "label": "free-team wildcard entitlements with data protection and inter-app audio",
            "include_push": False,
            "include_capabilities": False,
            "include_app_groups": False,
            "include_network_extension": False,
            "include_passbook": False,
            "include_siri": False,
            "include_icloud": False,
            "include_inter_app_audio": True,
            "include_data_protection": True,
        },
        {
            "label": "minimum wildcard entitlements",
            "include_push": False,
            "include_capabilities": False,
            "include_app_groups": False,
            "include_network_extension": False,
            "include_passbook": False,
            "include_siri": False,
            "include_icloud": False,
            "include_inter_app_audio": False,
            "include_data_protection": False,
        },
    ]


def update_app_id_for_maximum_entitlements(
    client: AppleDeveloperClient,
    team_id: str,
    session,
    app_id: dict[str, Any],
    certificate_type: str,
) -> dict[str, Any]:
    app_id_id = require_field(app_id, "appIdId", str, "Apple App ID")
    last_error: Exception | None = None
    for attempt in entitlement_attempts(certificate_type):
        label = str(attempt["label"])
        print(f"Updating wildcard App ID with {label}...")
        parameters = {
            "appIdId": app_id_id,
            **maximum_feature_parameters(
                include_push=bool(attempt["include_push"]),
                include_app_groups=bool(attempt["include_app_groups"]),
                include_network_extension=bool(attempt["include_network_extension"]),
                include_passbook=bool(attempt["include_passbook"]),
                include_siri=bool(attempt["include_siri"]),
                include_icloud=bool(attempt["include_icloud"]),
                include_inter_app_audio=bool(attempt["include_inter_app_audio"]),
                include_data_protection=bool(attempt["include_data_protection"]),
            ),
            "entitlements": maximum_entitlements(
                team_id,
                certificate_type,
                include_push=bool(attempt["include_push"]),
                include_app_groups=bool(attempt["include_app_groups"]),
                include_network_extension=bool(attempt["include_network_extension"]),
                include_passbook=bool(attempt["include_passbook"]),
                include_siri=bool(attempt["include_siri"]),
                include_icloud=bool(attempt["include_icloud"]),
                include_inter_app_audio=bool(attempt["include_inter_app_audio"]),
                include_data_protection=bool(attempt["include_data_protection"]),
            ),
        }
        if bool(attempt["include_capabilities"]):
            parameters["capabilities"] = MAXIMUM_CAPABILITIES
        try:
            response = client._send_developer_request(
                "ios/updateAppId.action",
                team_id=team_id,
                session=session,
                additional_parameters=parameters,
            )
        except AppleDeveloperServiceError as exc:
            last_error = exc
            print(f"Apple rejected {label}: {exc}")
            continue
        except FlowError as exc:
            last_error = exc
            print(f"Apple rejected {label}: {exc}")
            continue

        updated_app_id = response.get("appId")
        if not isinstance(updated_app_id, dict):
            raise FlowError("Apple did not return the updated App ID.")
        print(f"Apple accepted wildcard App ID update: {label}.")
        return updated_app_id

    if last_error is not None:
        raise last_error
    raise FlowError("Could not update the wildcard App ID.")


def profile_data_from_response(response: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    profile = response.get("provisioningProfile")
    if not isinstance(profile, dict):
        raise FlowError("Apple did not return a provisioning profile.")
    encoded_profile = profile.get("encodedProfile")
    if isinstance(encoded_profile, bytes):
        return encoded_profile, profile
    if isinstance(encoded_profile, str):
        return base64.b64decode(encoded_profile), profile
    raise FlowError("Apple returned a provisioning profile without encodedProfile data.")


def normalized_device_class(device: dict[str, Any]) -> str:
    return str(device.get("deviceClass", "")).replace(" ", "").replace("-", "").lower()


def device_ids_for_profile_platform(devices: list[dict[str, Any]], profile_platform: str) -> list[str]:
    config = PROFILE_PLATFORM_CONFIGS[profile_platform]
    device_classes = config["device_classes"]
    return [
        str(device["deviceId"])
        for device in devices
        if (
            isinstance(device, dict)
            and device.get("deviceId")
            and normalized_device_class(device) in device_classes
        )
    ]


def profile_platform_display_name(profile_platform: str) -> str:
    return str(PROFILE_PLATFORM_CONFIGS[profile_platform]["display_name"])


def profile_platform_parameter_attempts(profile_platform: str) -> list[dict[str, str]]:
    return list(PROFILE_PLATFORM_CONFIGS[profile_platform]["parameter_attempts"])


def resolve_profile_platforms(requested_platforms: list[str] | str, devices: list[dict[str, Any]]) -> list[str]:
    if requested_platforms != "auto":
        return requested_platforms

    platforms = [
        platform
        for platform in PROFILE_PLATFORM_CONFIGS
        if device_ids_for_profile_platform(devices, platform)
    ]
    if platforms:
        return platforms
    return ["ios"]


def profile_filename(profile_platform: str) -> str:
    return str(PROFILE_PLATFORM_CONFIGS[profile_platform]["filename"])


def download_provisioning_profile(
    client: AppleDeveloperClient,
    team_id: str,
    session,
    app_id: dict[str, Any],
    profile_platform: str,
) -> tuple[bytes, dict[str, Any]]:
    app_id_id = require_field(app_id, "appIdId", str, "Apple App ID")
    last_error: Exception | None = None
    for parameters in profile_platform_parameter_attempts(profile_platform):
        try:
            response = client._send_developer_request(
                "ios/downloadTeamProvisioningProfile.action",
                team_id=team_id,
                session=session,
                additional_parameters={
                    "appIdId": app_id_id,
                    **parameters,
                },
            )
            return profile_data_from_response(response)
        except (AppleDeveloperServiceError, FlowError) as exc:
            last_error = exc
            continue
    if last_error is not None:
        raise last_error
    raise FlowError(f"No platform parameters are configured for {profile_platform_display_name(profile_platform)}.")


def download_profile_by_id(client: AppleDeveloperClient, team_id: str, session, profile_id: str) -> tuple[bytes, dict[str, Any]]:
    response = client._send_developer_request(
        "ios/downloadProvisioningProfile.action",
        team_id=team_id,
        session=session,
        additional_parameters={
            "provisioningProfileId": profile_id,
        },
    )
    return profile_data_from_response(response)


def create_limited_provisioning_profile(
    client: AppleDeveloperClient,
    team_id: str,
    session,
    app_id: dict[str, Any],
    certificate_id: str,
    certificate_type: str,
    profile_platform: str,
    devices: list[dict[str, Any]],
) -> tuple[bytes, dict[str, Any]]:
    app_id_id = require_field(app_id, "appIdId", str, "Apple App ID")
    device_ids = device_ids_for_profile_platform(devices, profile_platform)
    if not device_ids:
        raise FlowError(
            f"Apple did not return any registered {profile_platform_display_name(profile_platform)} device IDs "
            "for a limited provisioning profile."
        )

    display_certificate_type = certificate_display_type(certificate_type)
    platform_name = profile_platform_display_name(profile_platform)
    print(f"Creating wildcard limited {display_certificate_type} {platform_name} profile for {len(device_ids)} registered device(s)...")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")
    safe_platform_name = platform_name.replace("/", "-")
    certificate_suffix = re.sub(r"[^A-Za-z0-9]", "", certificate_id)[:8] or "cert"
    profile_names = [
        f"SideStore Wildcard {platform_name} {display_certificate_type}",
        f"SideStore Wildcard {safe_platform_name} {display_certificate_type} {certificate_suffix} {timestamp}",
    ]
    last_error: Exception | None = None
    response: dict[str, Any] | None = None
    for profile_name in profile_names:
        for parameters in profile_platform_parameter_attempts(profile_platform):
            try:
                response = client._send_developer_request(
                    "ios/createProvisioningProfile.action",
                    team_id=team_id,
                    session=session,
                    additional_parameters={
                        "provisioningProfileName": profile_name,
                        "appIdId": app_id_id,
                        "certificateIds": [certificate_id],
                        "deviceIds": device_ids,
                        "distributionType": "limited",
                        **parameters,
                    },
                )
                break
            except AppleDeveloperServiceError as exc:
                last_error = exc
                if exc.result_code == 35 and profile_name == profile_names[0]:
                    print("Apple found duplicate profile names; retrying with a unique profile name.")
                    break
            except FlowError as exc:
                last_error = exc
        if response is not None:
            break
    else:
        if last_error is not None:
            raise last_error
        raise FlowError(f"No platform parameters are configured for {platform_name}.")

    if response is None:
        if last_error is not None:
            raise last_error
        raise FlowError(f"Apple did not create a {platform_name} provisioning profile.")

    try:
        return profile_data_from_response(response)
    except FlowError:
        profile = response.get("provisioningProfile")
        if not isinstance(profile, dict):
            raise
        profile_id = profile.get("provisioningProfileId")
        if not isinstance(profile_id, str) or not profile_id:
            raise
        return download_profile_by_id(client, team_id, session, profile_id)


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
    profile_exports: list[tuple[str, bytes, dict[str, Any]]],
    certificate_pem: bytes,
    private_key_pem: bytes,
    *,
    save_pem: bool,
    p12_password: str,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    p12_path = output_dir / PRIMARY_P12_FILENAME

    if not profile_exports:
        raise FlowError("No provisioning profiles were exported.")

    profile_paths = [output_dir / profile_filename(profile_platform) for profile_platform, _profile_data, _profile in profile_exports]
    current_outputs = {p12_path, *profile_paths}
    stale_generated_filenames = {
        "README.txt",
        "SideStoreSigningCertificate.p12",
        "SideStoreWildcard.mobileprovision",
        "SideStoreWildcard-iOS.mobileprovision",
        "SideStoreWildcard-tvOS.mobileprovision",
        "SideStoreWildcard-visionOS.mobileprovision",
        "Wildcard-tvOS.mobileprovision",
        "Wildcard-visionOS.mobileprovision",
    }
    for filename in stale_generated_filenames:
        stale_path = output_dir / filename
        if stale_path not in current_outputs and stale_path.exists():
            stale_path.unlink()

    p12_path.write_bytes(p12_data)
    for path, (_profile_platform, profile_data, _profile) in zip(profile_paths, profile_exports):
        path.write_bytes(profile_data)

    if save_pem:
        (output_dir / "certificate.pem").write_bytes(certificate_pem)
        (output_dir / "private_key.pem").write_bytes(private_key_pem)

    print()
    print("Exported signing assets:")
    print(f"  P12: {p12_path}")
    for profile_path in profile_paths:
        print(f"  Profile: {profile_path}")
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
    output_dir = Path(args.output_dir)

    client, session, team = authenticate(args, parser)
    team_id = require_field(team, "teamId", str, "Apple team selection")
    selected_certificate_type = select_certificate_type(args.certificate_type, team)

    if args.udid:
        ensure_device_registered(client, team_id, session, args.udid, args.device_name)

    app_id = find_or_create_app_id(
        client,
        team_id,
        session,
        args.bundle_id,
        args.app_id_name,
        replace_existing_wildcard_app_id=args.replace_existing_wildcard_app_id,
    )
    if not args.skip_max_entitlements:
        app_id = update_app_id_for_maximum_entitlements(client, team_id, session, app_id, selected_certificate_type)

    requested_certificate_type = selected_certificate_type
    if args.certificate_type == "auto" and selected_certificate_type == "distribution":
        requested_certificate_type = "auto"

    (
        certificate_type,
        private_key,
        private_key_pem,
        certificate,
        certificate_data,
        certificate_response,
    ) = get_or_create_signing_certificate(
        client,
        team_id,
        session,
        output_dir,
        args.machine_name,
        requested_certificate_type,
        p12_password=args.p12_password,
        force_new_certificate=args.force_new_certificate,
        allow_revoke_existing_certificate=args.allow_revoke_existing_certificate,
    )
    serial_number = format(certificate.serial_number, "X").lstrip("0")
    print(f"Created certificate serial: {serial_number}")

    if certificate_type != selected_certificate_type and not args.skip_max_entitlements:
        app_id = update_app_id_for_maximum_entitlements(client, team_id, session, app_id, certificate_type)

    certificate_id = certificate_identifier_from_response(certificate_response)
    if certificate_id is None:
        raise FlowError("Apple did not return the certificate ID needed for the provisioning profile.")

    devices = client.fetch_devices(team_id, session)
    profile_platforms = resolve_profile_platforms(args.profile_platforms, devices)
    print(
        "Provisioning profile platforms: "
        + ", ".join(profile_platform_display_name(platform) for platform in profile_platforms)
    )

    profile_exports: list[tuple[str, bytes, dict[str, Any]]] = []
    for profile_platform in profile_platforms:
        try:
            profile_data, profile = create_limited_provisioning_profile(
                client,
                team_id,
                session,
                app_id,
                certificate_id,
                certificate_type,
                profile_platform,
                devices,
            )
        except (AppleDeveloperServiceError, FlowError) as exc:
            if certificate_type != "development":
                raise
            print(f"Apple rejected explicit limited {profile_platform_display_name(profile_platform)} development profile creation: {exc}")
            print("Falling back to Apple team provisioning profile download.")
            profile_data, profile = download_provisioning_profile(client, team_id, session, app_id, profile_platform)
        print(
            "Downloaded "
            f"{profile_platform_display_name(profile_platform)} profile: "
            f"{profile.get('name') or profile.get('provisioningProfileId') or args.bundle_id}"
        )
        profile_exports.append((profile_platform, profile_data, profile))

    p12_data = serialize_p12(private_key, certificate, args.p12_password)
    write_outputs(
        output_dir,
        p12_data,
        profile_exports,
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
