#!/usr/bin/env python3
"""
Register or check an iOS device in an Apple developer account using the same
Apple developer services flow used by SideStore/AltSign.

This is intentionally verbose while the flow is being debugged. By default it
masks secret values in logs; pass --unsafe-debug-secrets to print them.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import hmac
import json
import locale as py_locale
import os
import plistlib
import re
import secrets
import ssl
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from typing import Any, Callable

try:
    import requests
    import truststore
    import websocket
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.padding import PKCS7
except ImportError as exc:
    if __name__ == "__main__" and not any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        print(
            "Missing dependency: {0}\n"
            "Install with:\n"
            "  python -m pip install -r scripts/register_apple_device_requirements.txt".format(exc.name),
            file=sys.stderr,
        )
        raise SystemExit(2)
    requests = None
    truststore = None
    websocket = None
    Cipher = None
    algorithms = None
    modes = None
    AESGCM = None
    PKCS7 = None


PROTOCOL_VERSION = "QH65B2"
CLIENT_ID = "XABBG36SBA"
DEVELOPER_SERVICES_BASE_URL = f"https://developerservices2.apple.com/services/{PROTOCOL_VERSION}/"
GSA_SERVICE_URL = "https://gsa.apple.com/grandslam/GsService2"
DEFAULT_ANISETTE_URL = "https://ani.sidestore.io"
APP_NAME = "com.apple.gs.xcode.auth"
PUBLIC_PAYLOAD_PREVIEW_LIMIT = 12

# RFC 5054 2048-bit N from Appendix A.
SRP_N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294"
    "3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D"
    "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB"
    "D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74"
    "7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A"
    "436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D"
    "5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73"
    "03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F"
    "9E4AFF73"
)
SRP_G = 2


class FlowError(RuntimeError):
    pass


class AppleDeveloperServiceError(FlowError):
    def __init__(self, result_code: int, message: str, payload: dict[str, Any]) -> None:
        super().__init__(f"Apple developer service error {result_code}: {message}")
        self.result_code = result_code
        self.payload = payload


class DebugPrinter:
    def __init__(self, enabled: bool, unsafe_secrets: bool) -> None:
        self.enabled = enabled
        self.unsafe_secrets = unsafe_secrets

    def __call__(self, message: str, value: Any | None = None, *, secret: bool = False) -> None:
        if not self.enabled:
            return

        timestamp = dt.datetime.now().strftime("%H:%M:%S")
        if value is None:
            print(f"[{timestamp}] {message}", file=sys.stderr)
            return

        if secret and not self.unsafe_secrets:
            rendered = self._masked(value)
        else:
            rendered = self._render(value)

        print(f"[{timestamp}] {message}: {rendered}", file=sys.stderr)

    def _render(self, value: Any) -> str:
        if isinstance(value, (bytes, bytearray)):
            return value.hex()
        try:
            return json.dumps(value, indent=2, sort_keys=True, default=str)
        except TypeError:
            return str(value)

    def _masked(self, value: Any) -> str:
        return self._render(self._mask_known(value))

    def _mask_scalar(self, value: Any) -> str:
        text = value.hex() if isinstance(value, (bytes, bytearray)) else str(value)
        if len(text) <= 8:
            return "***"
        return f"{text[:4]}...{text[-4:]}"

    def _mask_known(self, value: Any) -> Any:
        if isinstance(value, dict):
            redacted: dict[Any, Any] = {}
            for key, item in value.items():
                key_text = str(key).lower()
                if any(marker in key_text for marker in ("password", "token", "adi", "secret", "security-code")):
                    redacted[key] = self._mask_scalar(item)
                else:
                    redacted[key] = self._mask_known(item)
            return redacted
        if isinstance(value, list):
            return [self._mask_known(item) for item in value]
        return value


class VerificationCodeProvider:
    def __init__(self, code: str | None, env_var: str | None, stdin: bool) -> None:
        self.code = code
        self.env_var = env_var
        self.stdin = stdin
        self.used = False

    def __call__(self, label: str) -> str:
        if self.code is not None:
            return self._consume(self.code)
        if self.env_var is not None:
            value = os.environ.get(self.env_var)
            if not value:
                raise FlowError(f"Environment variable {self.env_var} is empty or not set.")
            return self._consume(value)
        if self.stdin:
            value = sys.stdin.readline().strip()
            if not value:
                raise FlowError("--2fa-stdin did not provide a verification code.")
            return self._consume(value)
        if not sys.stdin.isatty():
            raise FlowError("Verification code is required in non-interactive mode. Use --2fa-code, --2fa-env, or --2fa-stdin.")
        return input(f"{label}: ").strip()

    def _consume(self, value: str) -> str:
        if self.used:
            raise FlowError("A second verification code was required. Re-run interactively or without a one-time --2fa-code.")
        self.used = True
        return value.strip()


def now_iso_z() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_timezone_name() -> str:
    daylight = time.localtime().tm_isdst
    if daylight < 0:
        daylight = 0
    name = time.tzname[daylight] if time.tzname else ""
    abbreviations = {
        "Malay Peninsula Standard Time": "SGT",
        "Singapore Standard Time": "SGT",
        "China Standard Time": "CST",
        "Taipei Standard Time": "CST",
        "Tokyo Standard Time": "JST",
        "Korea Standard Time": "KST",
        "India Standard Time": "IST",
        "Pacific Standard Time": "PST",
        "Pacific Daylight Time": "PDT",
        "Mountain Standard Time": "MST",
        "Mountain Daylight Time": "MDT",
        "Central Standard Time": "CST",
        "Central Daylight Time": "CDT",
        "Eastern Standard Time": "EST",
        "Eastern Daylight Time": "EDT",
        "GMT Standard Time": "GMT",
        "UTC": "UTC",
    }
    if name in abbreviations:
        return abbreviations[name]
    if re.fullmatch(r"[A-Z]{2,5}", name):
        return name
    return "UTC"


def local_locale() -> str:
    if os.name == "nt":
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(85)
            result = ctypes.windll.kernel32.GetUserDefaultLocaleName(buffer, len(buffer))
            if result:
                locale_name = buffer.value.replace("-", "_")
                if locale_name:
                    return locale_name
        except Exception:
            pass

    candidates = [
        py_locale.getlocale()[0],
        os.environ.get("LC_ALL"),
        os.environ.get("LC_MESSAGES"),
        os.environ.get("LANG"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        normalized = candidate.split(".")[0].replace("-", "_")
        if normalized.upper() not in {"C", "POSIX"}:
            return normalized
    return "en_US"


def plist_dumps(value: Any) -> bytes:
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=False)


def plist_loads(data: bytes) -> Any:
    try:
        return plistlib.loads(data)
    except Exception as exc:
        raise FlowError("Response was not a valid plist.") from exc


def parse_plist_response(response: requests.Response, context: str) -> Any:
    try:
        return plist_loads(response.content)
    except FlowError:
        if not response.ok:
            body = response.text[:1000] if response.text else "(empty response)"
            raise FlowError(f"{context} failed with HTTP {response.status_code}: {body}")
        raise FlowError(f"{context} returned an invalid plist response.")


def require_field(mapping: dict[str, Any], key: str, expected_type: type | tuple[type, ...], context: str) -> Any:
    if not isinstance(mapping, dict):
        raise FlowError(f"{context} returned an invalid response object.")
    value = mapping.get(key)
    if not isinstance(value, expected_type):
        type_name = (
            " or ".join(item.__name__ for item in expected_type)
            if isinstance(expected_type, tuple)
            else expected_type.__name__
        )
        raise FlowError(f"{context} missing or invalid field '{key}' ({type_name} expected).")
    return value


def parse_int(value: Any, context: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise FlowError(f"{context} returned an invalid integer value: {value!r}") from exc


def raise_http_error(response: requests.Response, context: str) -> None:
    body = sanitize_error_body(response.text)
    raise FlowError(f"{context} failed with HTTP {response.status_code}: {body}")


def sanitize_error_body(text: str) -> str:
    if not text:
        return "(empty response)"
    body = text[:1000]
    patterns = [
        (r"([A-Za-z0-9_.-]*token[A-Za-z0-9_.-]*\s*[:=]\s*)[A-Za-z0-9+/=_.:-]+", True),
        (r"([A-Za-z0-9_.-]*adi[A-Za-z0-9_.-]*\s*[:=]\s*)[A-Za-z0-9+/=_.:-]+", True),
        (r"([A-Za-z0-9_.-]*identifier[A-Za-z0-9_.-]*\s*[:=]\s*)[A-Za-z0-9+/=_.:-]+", True),
        (r"([A-Fa-f0-9]{8}-[A-Fa-f0-9]{16}|[A-Fa-f0-9]{40})", False),
    ]
    for pattern, has_prefix in patterns:
        body = re.sub(
            pattern,
            lambda match: f"{match.group(1)}<redacted>" if has_prefix else "<redacted>",
            body,
            flags=re.IGNORECASE,
        )
    return body


def public_payload_preview(value: Any) -> Any:
    if isinstance(value, dict):
        preview: dict[str, Any] = {}
        for key, item in value.items():
            if str(key) in {"deviceNumber", "identifier", "teamId", "personId", "email"}:
                preview[str(key)] = "<redacted>"
            elif isinstance(item, (dict, list)):
                preview[str(key)] = f"<{type(item).__name__}>"
            else:
                preview[str(key)] = item
        return preview
    if isinstance(value, list):
        return {
            "count": len(value),
            "items": [public_payload_preview(item) for item in value[:PUBLIC_PAYLOAD_PREVIEW_LIMIT]],
        }
    return value


def validate_https_url(url: str, *, allow_http: bool) -> None:
    parsed = urlparse(url)
    if not parsed.netloc:
        raise FlowError("Anisette URL must include a host.")
    if parsed.username or parsed.password:
        raise FlowError("Anisette URL must not include embedded credentials.")
    if parsed.scheme == "https":
        return
    if allow_http and parsed.scheme == "http":
        print("WARNING: using insecure HTTP anisette URL; secrets may be exposed.", file=sys.stderr)
        return
    raise FlowError("Anisette URL must use https://. Pass --allow-insecure-anisette-http only for local testing.")


def is_relative_to(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def default_cache_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA", str(Path.home()))) / "SideStoreDeviceRegister"


def harden_user_cache_file(path: Path, label: str) -> None:
    if os.name == "nt":
        appdata = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        try:
            if appdata and is_relative_to(path, Path(appdata)):
                return
        except OSError:
            pass
        print(
            f"WARNING: {label} is outside the per-user app data directory; "
            "Windows ACL hardening is not applied by this script.",
            file=sys.stderr,
        )
        return

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def write_json_atomically(path: Path, payload: dict[str, Any], label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True)
    try:
        import tempfile

        fd, temporary_name = tempfile.mkstemp(
            prefix=f"{path.name}.",
            suffix=".tmp",
            dir=str(path.parent),
            text=True,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                file.write(text)
            os.replace(temporary_path, path)
            harden_user_cache_file(path, label)
        finally:
            if temporary_path.exists():
                try:
                    temporary_path.unlink()
                except OSError:
                    pass
    except OSError as exc:
        raise FlowError(f"Could not save {label}: {exc}") from exc


TLSVerify = str | bool | None


def configure_tls(tls_store: str, ca_bundle: str | None, allow_insecure_tls: bool, debug: DebugPrinter) -> TLSVerify:
    if allow_insecure_tls:
        requests.packages.urllib3.disable_warnings()
        print(
            "WARNING: TLS certificate verification is disabled. "
            "Use this only for temporary local debugging on a trusted network.",
            file=sys.stderr,
        )
        debug("TLS certificate verification", "disabled")
        return False

    if ca_bundle:
        path = Path(ca_bundle).expanduser()
        if not path.is_file():
            raise FlowError(f"CA bundle does not exist: {path}")
        os.environ["REQUESTS_CA_BUNDLE"] = str(path)
        debug("TLS CA bundle", str(path))
        return str(path)

    use_system_store = tls_store == "system" or (tls_store == "auto" and os.name == "nt")
    if use_system_store:
        truststore.inject_into_ssl()
        debug("TLS certificate store", "system")
    else:
        debug("TLS certificate store", "certifi")
    return None


def format_request_exception(exc: requests.RequestException) -> str:
    message = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" not in message and "trust provider" not in message:
        return message
    return (
        f"{message}\n"
        "TLS certificate verification failed. If this machine uses antivirus/proxy HTTPS inspection, "
        "install its root certificate into Windows Trusted Root Certification Authorities, pass "
        "--ca-bundle PATH_TO_ROOT_CA.pem, or temporarily retry with --allow-insecure-tls."
    )


def is_tls_verification_error(exc: BaseException) -> bool:
    message = str(exc)
    return (
        "CERTIFICATE_VERIFY_FAILED" in message
        or "trust provider" in message
        or "certificate verify failed" in message.lower()
    )


def ensure_apple_tls_or_prompt(verify: TLSVerify, debug: DebugPrinter) -> TLSVerify:
    if verify is False:
        return verify

    probe = requests.Session()
    if verify is not None:
        probe.verify = verify
    try:
        probe.get(GSA_SERVICE_URL, timeout=10)
        return verify
    except requests.RequestException as exc:
        if not is_tls_verification_error(exc):
            debug("Apple TLS probe failed without certificate error", format_request_exception(exc))
            return verify

        print(format_request_exception(exc), file=sys.stderr)
        if not sys.stdin.isatty():
            return verify

        answer = input("Disable TLS verification for this run and continue? [y/N]: ").strip().lower()
        if answer in {"y", "yes"}:
            requests.packages.urllib3.disable_warnings()
            print(
                "WARNING: TLS certificate verification is disabled for this run.",
                file=sys.stderr,
            )
            debug("TLS certificate verification", "disabled after interactive prompt")
            return False
        return verify


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, *chunks: bytes) -> bytes:
    mac = hmac.new(key, digestmod=hashlib.sha256)
    for chunk in chunks:
        mac.update(chunk)
    return mac.digest()


def int_to_bytes(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big")


class AppleSRP:
    def __init__(self, username: str, password: str, debug: DebugPrinter) -> None:
        self.username = username
        self.password = password
        self.debug = debug
        self.n = int(SRP_N_HEX, 16)
        self.g = SRP_G
        self.n_len = (self.n.bit_length() + 7) // 8
        self.a = 0
        while self.a == 0:
            self.a = secrets.randbits(256)
        self.a_pub = pow(self.g, self.a, self.n)
        if self.a_pub % self.n == 0:
            raise FlowError("Generated an invalid SRP public key.")
        self.session_key: bytes | None = None

    @property
    def public_key(self) -> bytes:
        return int_to_bytes(self.a_pub, self.n_len)

    def make_verification_message(self, salt: bytes, iterations: int, server_public_key: bytes, sp: str) -> bytes:
        b_pub = bytes_to_int(server_public_key)
        if b_pub % self.n == 0:
            raise FlowError("Apple returned an invalid SRP server public key.")

        password_digest = sha256(self.password.encode("utf-8"))
        if sp == "s2k_fo":
            password_input = password_digest.hex().encode("utf-8")
        else:
            password_input = password_digest

        # Match AltSign/CoreCrypto: GSA PBKDF2 output is passed to ccsrp_generate_x with noUsernameInX=true.
        derived_password_key = hashlib.pbkdf2_hmac("sha256", password_input, salt, iterations, dklen=32)
        x_bytes = sha256(salt + sha256(b":" + derived_password_key))
        x = bytes_to_int(x_bytes)

        padded_g = int_to_bytes(self.g, self.n_len)
        k = bytes_to_int(sha256(int_to_bytes(self.n, self.n_len) + padded_g))
        u = bytes_to_int(sha256(self.public_key + server_public_key.rjust(self.n_len, b"\0")))
        if u == 0:
            raise FlowError("Apple returned an invalid SRP scrambling parameter.")
        gx = pow(self.g, x, self.n)
        base = (b_pub - (k * gx)) % self.n
        exponent = self.a + (u * x)
        s = pow(base, exponent, self.n)
        self.session_key = sha256(int_to_bytes(s, self.n_len))

        h_n = sha256(int_to_bytes(self.n, self.n_len))
        h_g = sha256(padded_g)
        h_i = sha256(self.username.encode("utf-8"))
        h_xor = bytes(left ^ right for left, right in zip(h_n, h_g))
        m1 = sha256(
            h_xor
            + h_i
            + salt
            + self.public_key
            + server_public_key.rjust(self.n_len, b"\0")
            + self.session_key
        )

        self.debug("SRP salt", salt)
        self.debug("SRP iterations", iterations)
        self.debug("SRP sp", sp)
        self.debug("SRP A", self.public_key, secret=True)
        self.debug("SRP M1", m1, secret=True)
        return m1

    def verify_server(self, server_m2: bytes) -> bool:
        if self.session_key is None:
            return False
        expected = sha256(self.public_key + self.last_m1 + self.session_key) if hasattr(self, "last_m1") else None
        return expected is not None and hmac.compare_digest(expected, server_m2)

    def remember_m1(self, m1: bytes) -> None:
        self.last_m1 = m1

    def checksum(self, app_name: str, dsid: str) -> bytes:
        if self.session_key is None:
            raise FlowError("SRP session key is missing.")
        return hmac_sha256(
            self.session_key,
            b"apptokens",
            dsid.encode("utf-8"),
            app_name.encode("utf-8"),
        )

    def decrypt_extra_data(self, encrypted: bytes) -> bytes:
        if self.session_key is None:
            raise FlowError("SRP session key is missing.")

        key = hmac_sha256(self.session_key, b"extra data key:")
        iv = hmac_sha256(self.session_key, b"extra data iv:")[:16]
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    def decrypt_token(self, encrypted: bytes) -> bytes:
        if self.session_key is None:
            raise FlowError("SRP session key is missing.")

        version_size = 3
        iv_size = 16
        tag_size = 16
        if len(encrypted) <= version_size + iv_size + tag_size:
            raise FlowError("Encrypted token is too short.")

        version = encrypted[:version_size]
        iv = encrypted[version_size : version_size + iv_size]
        ciphertext = encrypted[version_size + iv_size :]
        aesgcm = AESGCM(self.session_key)
        return aesgcm.decrypt(iv, ciphertext, version)


@dataclass
class AnisetteData:
    machine_id: str
    one_time_password: str
    local_user_id: str
    routing_info: str
    device_unique_identifier: str
    device_serial_number: str
    device_description: str
    date: str
    locale: str
    time_zone: str

    def auth_client_dictionary(self) -> dict[str, Any]:
        return {
            "bootstrap": True,
            "icscrec": True,
            "pbe": False,
            "prkgen": True,
            "svct": "iCloud",
            "loc": self.locale,
            "X-Apple-Locale": self.locale,
            "X-Apple-I-MD": self.one_time_password,
            "X-Apple-I-MD-M": self.machine_id,
            "X-Mme-Device-Id": self.device_unique_identifier,
            "X-Apple-I-MD-LU": self.local_user_id,
            "X-Apple-I-MD-RINFO": int(self.routing_info),
            "X-Apple-I-SRL-NO": self.device_serial_number,
            "X-Apple-I-Client-Time": self.date,
            "X-Apple-I-TimeZone": self.time_zone,
        }

    def auth_headers(self) -> dict[str, str]:
        return {
            "X-MMe-Client-Info": self.device_description,
        }

    def developer_headers(self, dsid: str, auth_token: str) -> dict[str, str]:
        return {
            "Content-Type": "text/x-xml-plist",
            "User-Agent": "Xcode",
            "Accept": "text/x-xml-plist",
            "Accept-Language": "en-us",
            "X-Apple-App-Info": APP_NAME,
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Apple-I-Identity-Id": dsid,
            "X-Apple-GS-Token": auth_token,
            "X-Apple-I-MD-M": self.machine_id,
            "X-Apple-I-MD": self.one_time_password,
            "X-Apple-I-MD-LU": self.local_user_id,
            "X-Apple-I-MD-RINFO": self.routing_info,
            "X-Mme-Device-Id": self.device_unique_identifier,
            "X-MMe-Client-Info": self.device_description,
            "X-Apple-I-Client-Time": self.date,
            "X-Apple-Locale": self.locale,
            "X-Apple-I-Locale": self.locale,
            "X-Apple-I-TimeZone": self.time_zone,
        }

    def two_factor_headers(self, dsid: str, idms_token: str) -> dict[str, str]:
        identity_token = base64.b64encode(f"{dsid}:{idms_token}".encode("utf-8")).decode("ascii")
        return {
            "Accept": "application/x-buddyml",
            "Accept-Language": "en-us",
            "Content-Type": "application/x-plist",
            "User-Agent": "Xcode",
            "X-Apple-App-Info": APP_NAME,
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-I-MD-M": self.machine_id,
            "X-Apple-I-MD": self.one_time_password,
            "X-Apple-I-MD-LU": self.local_user_id,
            "X-Apple-I-MD-RINFO": self.routing_info,
            "X-Mme-Device-Id": self.device_unique_identifier,
            "X-MMe-Client-Info": self.device_description,
            "X-Apple-I-Client-Time": self.date,
            "X-Apple-Locale": self.locale,
            "X-Apple-I-TimeZone": self.time_zone,
        }


class AnisetteClient:
    def __init__(
        self,
        base_url: str,
        cache_path: Path,
        debug: DebugPrinter,
        verify: TLSVerify = None,
        mode: str = "auto",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.cache_path = cache_path
        self.debug = debug
        self.verify = verify
        self.mode = mode
        self.force_v1_for_run = False
        self.warned_v1 = False
        self.http = requests.Session()
        if verify is not None:
            self.http.verify = verify
        self.client_info: str | None = None
        self.user_agent: str | None = None
        self.identifier: str | None = None
        self.adi_pb: str | None = None

    def load_or_create(self, reset: bool = False) -> AnisetteData:
        if self.mode == "v1" or self.force_v1_for_run:
            return self._fetch_v1_headers()

        try:
            return self._load_or_create_v3(reset=reset)
        except FlowError as exc:
            if self.mode == "v3":
                raise
            self.debug("Anisette V3 failed; falling back to V1 endpoint", str(exc))
            self.force_v1_for_run = True
            return self._fetch_v1_headers()

    def _load_or_create_v3(self, reset: bool = False) -> AnisetteData:
        if reset and self.cache_path.exists():
            self.debug("Deleting anisette cache", str(self.cache_path))
            self.cache_path.unlink()

        self._load_cache()
        self._fetch_client_info()
        if not self.adi_pb:
            self._provision()
        return self._fetch_headers()

    def _fetch_v1_headers(self) -> AnisetteData:
        if not self.warned_v1:
            print(
                "WARNING: using anisette V1 fallback because V3 provisioning is unavailable. "
                "Prefer V3 when the server and network support it.",
                file=sys.stderr,
            )
            self.warned_v1 = True

        self.debug("Fetching anisette V1 headers", self.base_url)
        try:
            response = self.http.get(self.base_url, timeout=30)
        except requests.RequestException as exc:
            raise FlowError(f"Could not fetch anisette V1 headers: {format_request_exception(exc)}") from exc
        self.debug("anisette V1 status", response.status_code)
        try:
            payload = response.json()
        except ValueError as exc:
            raise FlowError("Anisette V1 endpoint did not return JSON.") from exc
        if not isinstance(payload, dict):
            raise FlowError("Anisette V1 endpoint did not return a JSON object.")
        if not response.ok:
            message = payload.get("message") if isinstance(payload.get("message"), str) else response.text[:500]
            raise FlowError(f"Anisette V1 endpoint returned HTTP {response.status_code}: {message}")
        self.debug("anisette V1 response", payload, secret=True)

        return AnisetteData(
            machine_id=require_field(payload, "X-Apple-I-MD-M", str, "Anisette V1 headers"),
            one_time_password=require_field(payload, "X-Apple-I-MD", str, "Anisette V1 headers"),
            routing_info=str(parse_int(require_field(payload, "X-Apple-I-MD-RINFO", (str, int), "Anisette V1 headers"), "Anisette V1 headers")),
            local_user_id=require_field(payload, "X-Apple-I-MD-LU", str, "Anisette V1 headers"),
            device_unique_identifier=require_field(payload, "X-Mme-Device-Id", str, "Anisette V1 headers"),
            device_serial_number=str(payload.get("X-Apple-I-SRL-NO") or "0"),
            device_description=require_field(payload, "X-MMe-Client-Info", str, "Anisette V1 headers"),
            date=str(payload.get("X-Apple-I-Client-Time") or now_iso_z()),
            locale=str(payload.get("X-Apple-Locale") or local_locale()),
            time_zone=str(payload.get("X-Apple-I-TimeZone") or local_timezone_name()),
        )

    def _load_cache(self) -> None:
        if not self.cache_path.exists():
            return

        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            identifier = data.get("identifier")
            adi_pb = data.get("adi_pb")
            if not isinstance(identifier, str) or len(base64.b64decode(identifier, validate=True)) != 16:
                raise ValueError("identifier must be a base64-encoded 16-byte value")
            if adi_pb is not None and (not isinstance(adi_pb, str) or not adi_pb.strip()):
                raise ValueError("adi_pb must be a non-empty string")
        except Exception as exc:
            self.debug("Ignoring invalid anisette cache; reprovisioning", str(exc))
            self.identifier = None
            self.adi_pb = None
            return

        self.identifier = identifier
        self.adi_pb = adi_pb
        self.debug("Loaded anisette cache", {"path": str(self.cache_path), "has_adi_pb": bool(self.adi_pb)})

    def _save_cache(self) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"identifier": self.identifier, "adi_pb": self.adi_pb}, indent=2)
        try:
            import tempfile

            fd, temporary_name = tempfile.mkstemp(
                prefix=f"{self.cache_path.name}.",
                suffix=".tmp",
                dir=str(self.cache_path.parent),
                text=True,
            )
            temporary_path = Path(temporary_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as file:
                    file.write(payload)
                os.replace(temporary_path, self.cache_path)
                self._harden_cache_file()
            finally:
                if temporary_path.exists():
                    try:
                        temporary_path.unlink()
                    except OSError:
                        pass
        except OSError as exc:
            raise FlowError(f"Could not save anisette cache: {exc}") from exc
        self.debug("Saved anisette cache", str(self.cache_path))

    def _harden_cache_file(self) -> None:
        harden_user_cache_file(self.cache_path, "anisette cache")

    def _fetch_client_info(self) -> None:
        url = f"{self.base_url}/v3/client_info"
        self.debug("Fetching anisette client_info", url)
        try:
            response = self.http.get(url, timeout=30)
        except requests.RequestException as exc:
            raise FlowError(f"Could not reach anisette v3 server {self.base_url}: {format_request_exception(exc)}") from exc
        self.debug("client_info status", response.status_code)
        try:
            payload = response.json()
        except ValueError as exc:
            raise FlowError("Anisette server did not return JSON. This script only supports v3 anisette servers.") from exc
        if not response.ok:
            message = payload.get("message") if isinstance(payload, dict) else response.text[:500]
            raise FlowError(f"Anisette v3 server returned HTTP {response.status_code}: {message}")
        if not isinstance(payload, dict):
            raise FlowError("Anisette server did not return a JSON object. This script only supports v3 anisette servers.")
        self.debug("client_info response", payload)

        self.client_info = payload.get("client_info")
        self.user_agent = payload.get("user_agent")
        if not isinstance(self.client_info, str) or not isinstance(self.user_agent, str):
            raise FlowError("Anisette server is not a compatible v3 server; missing client_info/user_agent.")
        if not self.identifier:
            raw_identifier = secrets.token_bytes(16)
            self.identifier = base64.b64encode(raw_identifier).decode("ascii")
            self.debug("Generated anisette identifier", self.identifier, secret=True)

    def _identifier_bytes(self) -> bytes:
        if not self.identifier:
            raise FlowError("Missing anisette identifier.")
        try:
            decoded = base64.b64decode(self.identifier, validate=True)
        except Exception as exc:
            raise FlowError("Anisette identifier cache is invalid. Retry with --reset-anisette-cache.") from exc
        if len(decoded) != 16:
            raise FlowError("Anisette identifier cache is invalid. Retry with --reset-anisette-cache.")
        return decoded

    def _local_user_id(self) -> str:
        return hashlib.sha256(self._identifier_bytes()).hexdigest().upper()

    def _device_id(self) -> str:
        return str(uuid.UUID(bytes=self._identifier_bytes())).upper()

    def _apple_provisioning_headers(self) -> dict[str, str]:
        if not self.client_info or not self.user_agent:
            raise FlowError("Missing anisette client info.")
        return {
            "X-Mme-Client-Info": self.client_info,
            "User-Agent": self.user_agent,
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "X-Apple-I-MD-LU": self._local_user_id(),
            "X-Mme-Device-Id": self._device_id(),
            "X-Apple-I-Client-Time": now_iso_z(),
            "X-Apple-Locale": local_locale(),
            "X-Apple-I-TimeZone": local_timezone_name(),
        }

    def _provision(self) -> None:
        self.debug("Provisioning anisette identity")
        try:
            lookup = self.http.get(
                f"{GSA_SERVICE_URL}/lookup",
                headers=self._apple_provisioning_headers(),
                timeout=30,
            )
        except requests.RequestException as exc:
            raise FlowError(f"Could not request Apple provisioning URLs: {format_request_exception(exc)}") from exc
        self.debug("GSA lookup status", lookup.status_code)
        self.debug("GSA lookup body", lookup.text[:2000], secret=True)
        lookup_plist = parse_plist_response(lookup, "Apple provisioning lookup")
        if not lookup.ok:
            raise_http_error(lookup, "Apple provisioning lookup")
        urls = require_field(lookup_plist, "urls", dict, "Apple provisioning lookup")
        start_url = require_field(urls, "midStartProvisioning", str, "Apple provisioning lookup")
        end_url = require_field(urls, "midFinishProvisioning", str, "Apple provisioning lookup")
        self.debug("Provisioning URLs", {"start": start_url, "end": end_url})

        ws_url = self.base_url.replace("https://", "wss://").replace("http://", "ws://")
        ws_url = f"{ws_url}/v3/provisioning_session"
        self.debug("Opening anisette provisioning websocket", ws_url)

        try:
            ssl_options = None
            if ws_url.startswith("wss://") and self.verify is False:
                ssl_options = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}
            elif ws_url.startswith("wss://") and isinstance(self.verify, str):
                ssl_options = {"ca_certs": self.verify}
            if ssl_options:
                ws = websocket.create_connection(ws_url, timeout=30, sslopt=ssl_options)
            else:
                ws = websocket.create_connection(ws_url, timeout=30)
        except Exception as exc:
            raise FlowError(f"Could not open anisette provisioning websocket: {exc}") from exc
        try:
            for _ in range(20):
                try:
                    message = ws.recv()
                    payload = json.loads(message)
                except Exception as exc:
                    raise FlowError(f"Anisette websocket returned invalid data: {exc}") from exc

                self.debug("Anisette websocket received", payload, secret=True)
                if not isinstance(payload, dict) or not isinstance(payload.get("result"), str):
                    raise FlowError("Anisette websocket response did not contain a result.")
                result = payload["result"]
                if result == "GiveIdentifier":
                    self._ws_send(ws, {"identifier": self.identifier})
                elif result == "GiveStartProvisioningData":
                    spim = self._start_provisioning_data(start_url)
                    self._ws_send(ws, {"spim": spim})
                elif result == "GiveEndProvisioningData":
                    cpim = payload.get("cpim")
                    if not cpim:
                        raise FlowError("Anisette server did not provide cpim.")
                    end_data = self._end_provisioning_data(end_url, cpim)
                    self._ws_send(ws, end_data)
                elif result == "ProvisioningSuccess":
                    self.adi_pb = payload.get("adi_pb")
                    if not self.adi_pb:
                        raise FlowError("Anisette server did not provide adi_pb.")
                    self.debug("Anisette provisioning succeeded")
                    self._save_cache()
                    return
                elif result and (
                    "Error" in result
                    or "Invalid" in result
                    or result in {"ClosingPerRequest", "Timeout", "TextOnly"}
                ):
                    raise FlowError(f"Anisette provisioning failed: {result} {payload.get('message') or ''}".strip())
                else:
                    self.debug("Ignoring unknown anisette websocket result", result)
            raise FlowError("Anisette provisioning websocket exceeded the maximum message count.")
        finally:
            ws.close()

    def _ws_send(self, ws: websocket.WebSocket, payload: dict[str, str | None]) -> None:
        clean_payload = {key: value for key, value in payload.items() if value is not None}
        self.debug("Anisette websocket sending", clean_payload, secret=True)
        ws.send(json.dumps(clean_payload))

    def _start_provisioning_data(self, url: str) -> str:
        body = plist_dumps({"Header": {}, "Request": {}})
        try:
            response = self.http.post(url, headers=self._apple_provisioning_headers(), data=body, timeout=30)
        except requests.RequestException as exc:
            raise FlowError(f"Could not start Apple anisette provisioning: {format_request_exception(exc)}") from exc
        self.debug("Start provisioning status", response.status_code)
        payload = parse_plist_response(response, "Apple start provisioning")
        if not response.ok:
            raise_http_error(response, "Apple start provisioning")
        self.debug("Start provisioning response", payload, secret=True)
        response_payload = require_field(payload, "Response", dict, "Apple start provisioning")
        return require_field(response_payload, "spim", str, "Apple start provisioning")

    def _end_provisioning_data(self, url: str, cpim: str) -> dict[str, str]:
        body = plist_dumps({"Header": {}, "Request": {"cpim": cpim}})
        try:
            response = self.http.post(url, headers=self._apple_provisioning_headers(), data=body, timeout=30)
        except requests.RequestException as exc:
            raise FlowError(f"Could not finish Apple anisette provisioning: {format_request_exception(exc)}") from exc
        self.debug("End provisioning status", response.status_code)
        payload = parse_plist_response(response, "Apple end provisioning")
        if not response.ok:
            raise_http_error(response, "Apple end provisioning")
        self.debug("End provisioning response", payload, secret=True)
        response_payload = require_field(payload, "Response", dict, "Apple end provisioning")
        return {
            "ptm": require_field(response_payload, "ptm", str, "Apple end provisioning"),
            "tk": require_field(response_payload, "tk", str, "Apple end provisioning"),
        }

    def _fetch_headers(self, stale_retry: bool = True) -> AnisetteData:
        if not self.identifier or not self.adi_pb:
            raise FlowError("Missing anisette provisioning cache.")

        url = f"{self.base_url}/v3/get_headers"
        self.debug("Fetching anisette headers", url)
        try:
            response = self.http.post(
                url,
                headers={"Content-Type": "application/json"},
                data=json.dumps({"identifier": self.identifier, "adi_pb": self.adi_pb}),
                timeout=30,
            )
        except requests.RequestException as exc:
            raise FlowError(f"Could not fetch anisette headers: {format_request_exception(exc)}") from exc
        self.debug("get_headers status", response.status_code)
        try:
            payload = response.json()
        except ValueError as exc:
            raise FlowError("Anisette get_headers did not return JSON.") from exc
        if not isinstance(payload, dict):
            raise FlowError("Anisette get_headers did not return a JSON object.")
        self.debug("get_headers response", payload, secret=True)

        if payload.get("result") == "GetHeadersError":
            message = str(payload.get("message") or "Unknown anisette GetHeadersError")
            if "-45061" in message or "adi" in message.lower() or "provision" in message.lower():
                if not stale_retry:
                    raise FlowError(f"Anisette cache remained invalid after reprovisioning: {message}")
                self.debug("Anisette cache is stale; resetting and reprovisioning")
                self.adi_pb = None
                self._save_cache()
                self._provision()
                return self._fetch_headers(stale_retry=False)
            raise FlowError(f"Anisette get_headers failed: {message}")
        if not response.ok:
            raise FlowError(f"Anisette get_headers returned HTTP {response.status_code}: {payload.get('message') or payload.get('result') or response.text[:500]}")

        return AnisetteData(
            machine_id=require_field(payload, "X-Apple-I-MD-M", str, "Anisette headers"),
            one_time_password=require_field(payload, "X-Apple-I-MD", str, "Anisette headers"),
            routing_info=str(parse_int(require_field(payload, "X-Apple-I-MD-RINFO", (str, int), "Anisette headers"), "Anisette headers")),
            local_user_id=self._local_user_id(),
            device_unique_identifier=self._device_id(),
            device_serial_number="0",
            device_description=self.client_info or str(payload.get("X-MMe-Client-Info", "")),
            date=now_iso_z(),
            locale=local_locale(),
            time_zone=local_timezone_name(),
        )


@dataclass
class AppleSession:
    dsid: str
    auth_token: str
    anisette: AnisetteData


class SessionStore:
    def __init__(self, path: Path, debug: DebugPrinter) -> None:
        self.path = path
        self.debug = debug

    def _key(self, apple_id: str) -> str:
        return hashlib.sha256(apple_id.strip().lower().encode("utf-8")).hexdigest()

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "sessions": {}}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as exc:
            self.debug("Ignoring invalid Apple session cache", str(exc))
            return {"version": 1, "sessions": {}}
        if not isinstance(payload, dict):
            return {"version": 1, "sessions": {}}
        sessions = payload.get("sessions")
        if not isinstance(sessions, dict):
            payload["sessions"] = {}
        return payload

    def _write(self, payload: dict[str, Any]) -> None:
        write_json_atomically(self.path, payload, "Apple session cache")
        self.debug("Saved Apple session cache", str(self.path))

    def load(self, apple_id: str, anisette: AnisetteData) -> AppleSession | None:
        payload = self._read()
        sessions = payload.get("sessions", {})
        if not isinstance(sessions, dict):
            return None
        entry = sessions.get(self._key(apple_id))
        if not isinstance(entry, dict):
            return None
        dsid = entry.get("dsid")
        auth_token = entry.get("auth_token")
        if not isinstance(dsid, str) or not isinstance(auth_token, str) or not dsid or not auth_token:
            self.delete(apple_id)
            return None
        self.debug(
            "Loaded cached Apple session",
            {
                "path": str(self.path),
                "created_at": entry.get("created_at"),
                "last_used_at": entry.get("last_used_at"),
                "auth_token": auth_token,
            },
            secret=True,
        )
        return AppleSession(dsid=dsid, auth_token=auth_token, anisette=anisette)

    def save(self, apple_id: str, session: AppleSession) -> None:
        payload = self._read()
        sessions = payload.setdefault("sessions", {})
        if not isinstance(sessions, dict):
            sessions = {}
            payload["sessions"] = sessions
        key = self._key(apple_id)
        existing = sessions.get(key) if isinstance(sessions.get(key), dict) else {}
        created_at = existing.get("created_at") if isinstance(existing, dict) else None
        now = now_iso_z()
        sessions[key] = {
            "created_at": created_at or now,
            "last_used_at": now,
            "dsid": session.dsid,
            "auth_token": session.auth_token,
        }
        self._write(payload)

    def delete(self, apple_id: str) -> None:
        payload = self._read()
        sessions = payload.get("sessions", {})
        if not isinstance(sessions, dict):
            return
        if sessions.pop(self._key(apple_id), None) is not None:
            self._write(payload)


class AppleDeveloperClient:
    def __init__(self, anisette: AnisetteData, debug: DebugPrinter, verify: TLSVerify = None) -> None:
        self.anisette = anisette
        self.debug = debug
        self.http = requests.Session()
        if verify is not None:
            self.http.verify = verify
        self.refresh_anisette: Callable[[], AnisetteData] | None = None
        self.anisette_fetched_at = time.monotonic()

    def set_anisette_refresh(self, refresh: Callable[[], AnisetteData]) -> None:
        self.refresh_anisette = refresh

    def refresh_anisette_if_needed(self, max_age_seconds: float = 30.0, *, force: bool = False) -> None:
        if self.refresh_anisette is None:
            return
        if force or time.monotonic() - self.anisette_fetched_at > max_age_seconds:
            self.debug("Refreshing anisette headers")
            self.anisette = self.refresh_anisette()
            self.anisette_fetched_at = time.monotonic()

    def authenticate(
        self,
        apple_id: str,
        password: str,
        verification_prompt: Callable[[str], str],
        max_attempts: int = 4,
    ) -> tuple[dict[str, Any], AppleSession]:
        sanitized = apple_id.lower()
        for attempt in range(1, max_attempts + 1):
            self.refresh_anisette_if_needed(force=attempt > 1)
            self.debug(f"Starting Apple authentication attempt {attempt}")
            result = self._authenticate_once(sanitized, password, verification_prompt)
            if result is not None:
                return result
        raise FlowError("Authentication did not complete after repeated 2FA attempts.")

    def _authenticate_once(
        self,
        apple_id: str,
        password: str,
        verification_prompt: Callable[[str], str],
    ) -> tuple[dict[str, Any], AppleSession] | None:
        context = AppleSRP(apple_id, password, self.debug)
        client_dictionary = self.anisette.auth_client_dictionary()

        init_request = {
            "A2k": context.public_key,
            "cpd": client_dictionary,
            "ps": ["s2k", "s2k_fo"],
            "o": "init",
            "u": apple_id,
        }
        init_response = self._send_auth_request(init_request)
        self.debug("Auth init response", init_response, secret=True)

        challenge = require_field(init_response, "c", str, "Apple auth init")
        salt = require_field(init_response, "s", bytes, "Apple auth init")
        iterations = parse_int(require_field(init_response, "i", (int, str), "Apple auth init"), "Apple auth init")
        server_public_key = require_field(init_response, "B", bytes, "Apple auth init")
        sp = init_response.get("sp", "s2k")
        if not isinstance(sp, str):
            raise FlowError("Apple auth init returned invalid field 'sp'.")
        m1 = context.make_verification_message(salt, iterations, server_public_key, sp)
        context.remember_m1(m1)

        complete_request = {
            "c": challenge,
            "cpd": client_dictionary,
            "M1": m1,
            "o": "complete",
            "u": apple_id,
        }
        complete_response = self._send_auth_request(complete_request)
        self.debug("Auth complete response", complete_response, secret=True)

        server_m2 = require_field(complete_response, "M2", bytes, "Apple auth complete")
        if not context.verify_server(server_m2):
            raise FlowError("Apple SRP server verification failed.")

        encrypted_server_dictionary = require_field(complete_response, "spd", bytes, "Apple auth complete")
        decrypted_server_dictionary = plist_loads(context.decrypt_extra_data(encrypted_server_dictionary))
        if not isinstance(decrypted_server_dictionary, dict):
            raise FlowError("Apple auth complete returned invalid encrypted server dictionary.")
        self.debug("Decrypted auth server dictionary", decrypted_server_dictionary, secret=True)

        dsid = require_field(decrypted_server_dictionary, "adsid", str, "Apple auth complete")
        idms_token = require_field(decrypted_server_dictionary, "GsIdmsToken", str, "Apple auth complete")
        auth_type = complete_response.get("Status", {}).get("au")
        self.debug("Auth type", auth_type or "none")

        if auth_type == "trustedDeviceSecondaryAuth":
            self._request_trusted_device_two_factor(dsid, idms_token, verification_prompt)
            return None
        if auth_type == "secondaryAuth":
            self._request_sms_two_factor(dsid, idms_token, verification_prompt)
            return None

        session_key = require_field(decrypted_server_dictionary, "sk", bytes, "Apple auth complete")
        c_value = require_field(decrypted_server_dictionary, "c", bytes, "Apple auth complete")
        context.session_key = session_key
        checksum = context.checksum(APP_NAME, dsid)
        token_request = {
            "app": [APP_NAME],
            "c": c_value,
            "checksum": checksum,
            "cpd": client_dictionary,
            "o": "apptokens",
            "t": idms_token,
            "u": dsid,
        }
        token_response = self._send_auth_request(token_request)
        self.debug("Token response", token_response, secret=True)
        encrypted_token = require_field(token_response, "et", bytes, "Apple auth token")
        token_plist = plist_loads(context.decrypt_token(encrypted_token))
        if not isinstance(token_plist, dict):
            raise FlowError("Apple token response decrypted to an invalid plist.")
        self.debug("Decrypted token plist", token_plist, secret=True)
        token_apps = require_field(token_plist, "t", dict, "Apple auth token")
        app_token = require_field(token_apps, APP_NAME, dict, "Apple auth token")
        auth_token = require_field(app_token, "token", str, "Apple auth token")

        session = AppleSession(dsid=dsid, auth_token=auth_token, anisette=self.anisette)
        account = self.fetch_account(session)
        return account, session

    def _send_auth_request(self, request_parameters: dict[str, Any]) -> dict[str, Any]:
        body = plist_dumps({"Header": {"Version": "1.0.1"}, "Request": request_parameters})
        headers = {
            "Content-Type": "text/x-xml-plist",
            "X-MMe-Client-Info": self.anisette.device_description,
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
        }
        try:
            response = self.http.post(GSA_SERVICE_URL, headers=headers, data=body, timeout=30)
        except requests.RequestException as exc:
            raise FlowError(f"Apple authentication request failed: {format_request_exception(exc)}") from exc
        self.debug("GSA auth HTTP status", response.status_code)
        self.debug("GSA auth raw response", response.content[:2000], secret=True)
        payload = parse_plist_response(response, "Apple authentication")
        dictionary = require_field(payload, "Response", dict, "Apple authentication")
        if not isinstance(dictionary, dict):
            raise FlowError("Apple returned an invalid authentication response.")

        status = dictionary.get("Status", {})
        if not isinstance(status, dict):
            raise FlowError("Apple authentication returned an invalid Status field.")
        error_code = parse_int(status.get("ec", 0), "Apple authentication")
        if error_code == 0:
            return dictionary
        if error_code in {-20101, -22406}:
            raise FlowError("Apple rejected the username or password.")
        if error_code == -22421:
            raise FlowError("Apple rejected the anisette data. Try --reset-anisette-cache.")
        if not response.ok:
            raise_http_error(response, "Apple authentication")
        raise FlowError(f"Apple authentication error {error_code}: {status.get('em')}")

    def _request_trusted_device_two_factor(
        self,
        dsid: str,
        idms_token: str,
        verification_prompt: Callable[[str], str],
    ) -> None:
        self.debug("Requesting trusted-device 2FA code")
        headers = self.anisette.two_factor_headers(dsid, idms_token)
        try:
            request_response = self.http.get("https://gsa.apple.com/auth/verify/trusteddevice", headers=headers, timeout=30)
        except requests.RequestException as exc:
            raise FlowError(f"Could not request trusted-device 2FA code: {format_request_exception(exc)}") from exc
        self.debug("Trusted-device request status", request_response.status_code)
        if not request_response.ok:
            raise_http_error(request_response, "Trusted-device 2FA request")

        code = verification_prompt("Enter trusted-device 2FA code")
        verify_headers = dict(headers)
        verify_headers["security-code"] = code
        try:
            verify_response = self.http.get(
                "https://gsa.apple.com/grandslam/GsService2/validate",
                headers=verify_headers,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise FlowError(f"Could not verify trusted-device 2FA code: {format_request_exception(exc)}") from exc
        self.debug("Trusted-device verify status", verify_response.status_code)
        payload = parse_plist_response(verify_response, "Trusted-device verification")
        if not verify_response.ok:
            raise_http_error(verify_response, "Trusted-device verification")
        self.debug("Trusted-device verify response", payload, secret=True)
        error_code = parse_int(payload.get("ec", 0), "Trusted-device verification")
        if error_code != 0:
            raise FlowError(f"Incorrect or rejected 2FA code: {payload.get('em')} ({error_code})")

    def _request_sms_two_factor(
        self,
        dsid: str,
        idms_token: str,
        verification_prompt: Callable[[str], str],
    ) -> None:
        self.debug("Requesting SMS 2FA code")
        headers = self.anisette.two_factor_headers(dsid, idms_token)
        body = plist_dumps({"serverInfo": {"phoneNumber.id": "1"}})
        try:
            request_response = self.http.post(
                "https://gsa.apple.com/auth/verify/phone/put?mode=sms",
                headers=headers,
                data=body,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise FlowError(f"Could not request SMS verification code: {format_request_exception(exc)}") from exc
        self.debug("SMS request status", request_response.status_code)
        if not request_response.ok:
            raise_http_error(request_response, "SMS verification request")

        code = verification_prompt("Enter SMS verification code")
        verify_body = plist_dumps(
            {
                "securityCode.code": code,
                "serverInfo": {"mode": "sms", "phoneNumber.id": "1"},
            }
        )
        try:
            verify_response = self.http.post(
                "https://gsa.apple.com/auth/verify/phone/securitycode?referrer=/auth/verify/phone/put",
                headers=headers,
                data=verify_body,
                timeout=30,
            )
        except requests.RequestException as exc:
            raise FlowError(f"Could not verify SMS code: {format_request_exception(exc)}") from exc
        self.debug("SMS verify status", verify_response.status_code)
        self.debug("SMS verify headers", dict(verify_response.headers), secret=True)
        if verify_response.status_code != 200 or "X-Apple-PE-Token" not in verify_response.headers:
            raise FlowError("Incorrect or rejected SMS verification code.")

    def fetch_account(self, session: AppleSession) -> dict[str, Any]:
        self.refresh_anisette_if_needed()
        session.anisette = self.anisette
        response = self._send_developer_request("viewDeveloper.action", session=session)
        account = response.get("developer")
        if not isinstance(account, dict):
            raise FlowError("Apple did not return a developer account.")
        self.debug("Developer account", public_payload_preview(account))
        return account

    def fetch_teams(self, account: dict[str, Any], session: AppleSession) -> list[dict[str, Any]]:
        self.refresh_anisette_if_needed()
        session.anisette = self.anisette
        response = self._send_developer_request("listTeams.action", session=session)
        teams = response.get("teams")
        if not isinstance(teams, list):
            raise FlowError("Apple did not return teams.")
        self.debug("Teams", public_payload_preview(teams))
        if not teams:
            raise FlowError("No Apple developer teams found.")
        return teams

    def fetch_devices(self, team_id: str, session: AppleSession) -> list[dict[str, Any]]:
        self.refresh_anisette_if_needed()
        session.anisette = self.anisette
        response = self._send_developer_request("ios/listDevices.action", team_id=team_id, session=session)
        devices = response.get("devices")
        if not isinstance(devices, list):
            raise FlowError("Apple did not return devices.")
        self.debug("Devices", public_payload_preview(devices))
        return devices

    def add_device(self, team_id: str, udid: str, name: str, session: AppleSession) -> dict[str, Any]:
        self.refresh_anisette_if_needed()
        session.anisette = self.anisette
        response = self._send_developer_request(
            "ios/addDevice.action",
            team_id=team_id,
            session=session,
            additional_parameters={
                "deviceNumber": udid,
                "name": name,
                "DTDK_Platform": "ios",
            },
        )
        device = response.get("device")
        if not isinstance(device, dict):
            raise FlowError("Apple did not return the newly registered device.")
        self.debug("Add device response", public_payload_preview(response))
        return device

    def _send_developer_request(
        self,
        action: str,
        *,
        session: AppleSession,
        team_id: str | None = None,
        additional_parameters: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        parameters: dict[str, Any] = {
            "clientId": CLIENT_ID,
            "protocolVersion": PROTOCOL_VERSION,
            "requestId": str(uuid.uuid4()).upper(),
        }
        if team_id:
            parameters["teamId"] = team_id
        if additional_parameters:
            parameters.update(additional_parameters)

        url = f"{DEVELOPER_SERVICES_BASE_URL}{action}?clientId={CLIENT_ID}"
        headers = self.anisette.developer_headers(session.dsid, session.auth_token)
        body = plist_dumps(parameters)
        self.debug("Developer request URL", url)
        self.debug("Developer request parameters", parameters)
        self.debug("Developer request headers", headers, secret=True)
        try:
            response = self.http.post(url, headers=headers, data=body, timeout=30)
        except requests.RequestException as exc:
            raise FlowError(f"Apple developer service request failed for {action}: {format_request_exception(exc)}") from exc
        self.debug("Developer response status", response.status_code)
        self.debug("Developer raw response", response.content[:4000], secret=True)
        payload = parse_plist_response(response, f"Apple developer service {action}")
        if not isinstance(payload, dict):
            raise FlowError(f"Apple developer service {action} returned an invalid plist.")
        self.debug("Developer response plist", public_payload_preview(payload))

        result_code = parse_int(payload.get("resultCode", 0), f"Apple developer service {action}")
        if result_code != 0:
            message = payload.get("userString") or payload.get("resultString") or "Unknown Apple error"
            raise AppleDeveloperServiceError(result_code, message, payload)
        if not response.ok:
            raise_http_error(response, f"Apple developer service {action}")
        return payload


def normalize_udid(udid: str) -> str:
    clean = udid.strip()
    if not clean:
        raise FlowError("UDID is required.")
    if not re.fullmatch(r"(?:[A-Fa-f0-9]{40}|[A-Fa-f0-9]{8}-[A-Fa-f0-9]{16})", clean):
        raise FlowError("UDID must be 40 hex characters or the modern 8-16 hex format, e.g. 00008030-001C195E02D8802E.")
    return clean


def find_device(devices: list[dict[str, Any]], udid: str) -> dict[str, Any] | None:
    normalized = udid.replace("-", "").lower()
    for device in devices:
        device_number = str(device.get("deviceNumber", ""))
        if device_number.replace("-", "").lower() == normalized:
            return device
    return None


def parse_possible_date(value: Any) -> dt.datetime | None:
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc)
    if isinstance(value, dt.date):
        return dt.datetime.combine(value, dt.time.min, tzinfo=dt.timezone.utc)
    text = str(value).strip()
    if not text:
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%m/%d/%Y",
        "%d/%m/%Y",
    ]
    for fmt in formats:
        try:
            parsed = dt.datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            pass
    return None


def iter_nested_records(value: Any) -> Any:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from iter_nested_records(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_nested_records(item)


def extract_expiration_fields(*records: dict[str, Any]) -> list[tuple[str, Any, dt.datetime | None]]:
    names = {
        "expirationDate",
        "expiryDate",
        "expires",
        "dateExpires",
        "membershipExpirationDate",
        "deviceExpiration",
        "expiration",
        "validUntil",
    }
    found: list[tuple[str, Any, dt.datetime | None]] = []
    for record in records:
        for key, value in record.items():
            if key in names or "expir" in key.lower() or "validuntil" in key.lower():
                found.append((key, value, parse_possible_date(value)))
    return found


def extract_nested_expiration_fields(record: dict[str, Any]) -> list[tuple[str, Any, dt.datetime | None]]:
    found: list[tuple[str, Any, dt.datetime | None]] = []
    for nested in iter_nested_records(record):
        found.extend(extract_expiration_fields(nested))
    return found


def first_present(record: dict[str, Any], keys: list[str]) -> tuple[str, Any] | None:
    for key in keys:
        if key in record:
            return key, record[key]
    return None


def classify_team(team: dict[str, Any]) -> str:
    team_type = str(team.get("type", "Unknown"))
    if team_type == "Company/Organization":
        return "Organization"
    if team_type == "Individual":
        memberships = team.get("memberships")
        if isinstance(memberships, list) and len(memberships) == 1:
            membership = memberships[0]
            if isinstance(membership, dict) and "free" in str(membership.get("name", "")).lower():
                return "Free"
        return "Individual"
    return team_type


def summarize_device_status(device: dict[str, Any] | None, team: dict[str, Any], *, show_raw: bool) -> None:
    print()
    print("Device Status")
    print("-------------")
    if device is None:
        print("Registered: no")
        print("Approval: not registered in this Apple developer team")
        print("How long: none, because the device has not been added yet")
        print_team_duration(team)
        return

    print("Registered: yes")
    print(f"Name: {device.get('name', '(unknown)')}")
    print(f"UDID: {device.get('deviceNumber', '(unknown)')}")
    print(f"Device class: {device.get('deviceClass', '(unknown)')}")

    status_field = first_present(
        device,
        ["status", "deviceStatus", "approvalStatus", "enabled", "isEnabled"],
    )
    if status_field is None:
        print("Approval: registered; Apple listDevices returned no separate approval field")
    else:
        print(f"Approval ({status_field[0]}): {status_field[1]}")

    device_expirations = extract_nested_expiration_fields(device)
    if not device_expirations:
        print("How long: Apple listDevices returned no per-device expiration field")
    else:
        now = dt.datetime.now(dt.timezone.utc)
        for key, value, parsed in device_expirations:
            if parsed is None:
                print(f"How long ({key}): {value}")
            else:
                remaining = parsed - now
                days = remaining.days
                print(f"How long ({key}): {value} ({days} days remaining)")

    print_team_duration(team)

    if show_raw:
        print()
        print("Raw device record:")
        print(json.dumps(device, indent=2, sort_keys=True, default=str))


def print_team_duration(team: dict[str, Any]) -> None:
    team_expirations = extract_nested_expiration_fields(team)
    if team_expirations:
        now = dt.datetime.now(dt.timezone.utc)
        for key, value, parsed in team_expirations:
            if parsed is None:
                print(f"Team/membership duration ({key}): {value}")
            else:
                remaining = parsed - now
                print(f"Team/membership duration ({key}): {value} ({remaining.days} days remaining)")


def choose_team(teams: list[dict[str, Any]], requested_team_id: str | None) -> dict[str, Any]:
    if requested_team_id:
        requested_team_id = requested_team_id.strip()
        for team in teams:
            if team.get("teamId") == requested_team_id:
                validate_team(team)
                return team
        raise FlowError(f"Team ID {requested_team_id} was not returned by Apple.")

    if len(teams) == 1:
        validate_team(teams[0])
        return teams[0]

    print()
    print("Apple returned multiple teams:")
    for index, team in enumerate(teams, start=1):
        print(f"  {index}. {team.get('name')} ({team.get('teamId')}) type={classify_team(team)}")

    while True:
        if not sys.stdin.isatty():
            raise FlowError("Multiple Apple teams were returned. Re-run with --team-id in non-interactive mode.")
        answer = input("Choose team number: ").strip()
        try:
            index = int(answer)
        except ValueError:
            print("Enter a number.")
            continue
        if 1 <= index <= len(teams):
            team = teams[index - 1]
            validate_team(team)
            return team
        print("Invalid team number.")


def validate_team(team: dict[str, Any]) -> None:
    team_id = team.get("teamId")
    if not isinstance(team_id, str) or not team_id:
        raise FlowError("Apple returned a malformed team without a teamId.")


def prompt_missing(args: argparse.Namespace, parser: argparse.ArgumentParser, *, need_password: bool) -> None:
    def require_interactive(label: str) -> None:
        if not sys.stdin.isatty():
            parser.error(f"{label} is required in non-interactive mode.")

    if not args.mode:
        require_interactive("--mode")
        while True:
            print("Choose action:")
            print("  1. Check current device status")
            print("  2. Add/register new device")
            answer = input("Action [1]: ").strip() or "1"
            if answer == "1":
                args.mode = "check"
                break
            if answer == "2":
                args.mode = "add"
                break
            print("Enter 1 or 2.")

    if not args.udid:
        require_interactive("--udid")
        args.udid = input("Device UDID: ").strip()

    if args.mode == "add" and not args.device_name:
        require_interactive("--device-name")
        args.device_name = input("Device name [iPhone]: ").strip() or "iPhone"

    if not args.apple_id:
        require_interactive("--apple-id")
        args.apple_id = input("Apple ID email: ").strip()

    if not need_password:
        return

    resolve_password(args, parser)


def resolve_password(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    def require_interactive(label: str) -> None:
        if not sys.stdin.isatty():
            parser.error(f"{label} is required in non-interactive mode.")

    if args.password_env:
        args.password = os.environ.get(args.password_env)
        if not args.password:
            parser.error(f"Environment variable {args.password_env} is empty or not set.")
    elif args.password_stdin:
        args.password = sys.stdin.readline().rstrip("\r\n")
        if not args.password:
            parser.error("--password-stdin did not provide a password.")
    else:
        require_interactive("Apple ID password")
        args.password = getpass.getpass("Apple ID password: ")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Register or check an Apple developer device.")
    parser.add_argument("--mode", choices=["add", "check"], help="Action to perform. Omit for an interactive menu.")
    parser.add_argument("--udid", help="Target iPhone/iPad UDID.")
    parser.add_argument("--device-name", help="Device name to send when registering.")
    parser.add_argument("--apple-id", help="Apple ID email.")
    parser.add_argument("--password-env", help="Read Apple ID password from this environment variable.")
    parser.add_argument("--password-stdin", action="store_true", help="Read Apple ID password from stdin.")
    parser.add_argument("--2fa-code", dest="two_factor_code", help="Verification code to use once.")
    parser.add_argument("--2fa-env", dest="two_factor_env", help="Read verification code from this environment variable.")
    parser.add_argument("--2fa-stdin", dest="two_factor_stdin", action="store_true", help="Read verification code from stdin when prompted.")
    parser.add_argument("--team-id", help="Apple developer team ID. Omit to auto-select or prompt.")
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
    parser.add_argument(
        "--allow-insecure-tls",
        action="store_true",
        help="Disable HTTPS certificate verification. Temporary debugging only.",
    )
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
    parser.set_defaults(debug=True)
    parser.add_argument("--debug", dest="debug", action="store_true", help="Print verbose debug logs. Enabled by default; secrets are redacted.")
    parser.add_argument("--quiet", dest="debug", action="store_false", help="Disable debug logs.")
    parser.add_argument("--raw", action="store_true", help="Print raw device records even when --quiet is used.")
    parser.add_argument(
        "--unsafe-debug-secrets",
        action="store_true",
        help="Print passwords/tokens/anisette secrets in debug logs. Use only on a private machine.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        parser.parse_args()
        return 0

    if sys.version_info < (3, 10):
        print("Python 3.10 or newer is required.", file=sys.stderr)
        return 2

    if requests is None or truststore is None or websocket is None or Cipher is None or algorithms is None or modes is None or AESGCM is None or PKCS7 is None:
        print(
            "Missing runtime dependencies.\n"
            "Install with:\n"
            "  python -m pip install -r scripts/register_apple_device_requirements.txt",
            file=sys.stderr,
        )
        return 2

    args = parser.parse_args()
    if args.password_env and args.password_stdin:
        parser.error("Use only one of --password-env or --password-stdin.")
    if args.allow_insecure_tls and args.ca_bundle:
        parser.error("Use only one of --allow-insecure-tls or --ca-bundle.")
    two_factor_sources = sum(bool(value) for value in (args.two_factor_code, args.two_factor_env, args.two_factor_stdin))
    if two_factor_sources > 1:
        parser.error("Use only one of --2fa-code, --2fa-env, or --2fa-stdin.")

    prompt_missing(args, parser, need_password=False)
    validate_https_url(args.anisette_url, allow_http=args.allow_insecure_anisette_http)

    debug = DebugPrinter(enabled=args.debug, unsafe_secrets=args.unsafe_debug_secrets)
    verify = configure_tls(args.tls_trust_store, args.ca_bundle, args.allow_insecure_tls, debug)
    verify = ensure_apple_tls_or_prompt(verify, debug)
    udid = normalize_udid(args.udid)
    cache_path = Path(args.cache)
    session_store = None if args.no_session_cache else SessionStore(Path(args.session_cache), debug)
    if args.reset_session_cache and session_store is not None:
        session_store.delete(args.apple_id)

    verification_prompt = VerificationCodeProvider(
        args.two_factor_code,
        args.two_factor_env,
        args.two_factor_stdin,
    )

    debug("Mode", args.mode)
    debug("Target UDID", udid)
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
    session: AppleSession | None = None
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

    devices = client.fetch_devices(team_id, session)
    existing = find_device(devices, udid)

    if args.mode == "check":
        summarize_device_status(existing, team, show_raw=args.raw)
        return 0

    if existing is not None:
        print()
        print("Device is already registered. No add request was sent.")
        summarize_device_status(existing, team, show_raw=args.raw)
        return 0

    print()
    print(f"Registering device {args.device_name} ({udid})...")
    try:
        added = client.add_device(team_id, udid, args.device_name, session)
    except AppleDeveloperServiceError as exc:
        if exc.result_code == 35:
            apple_message = str(exc)
            refreshed_devices = client.fetch_devices(team_id, session)
            refreshed = find_device(refreshed_devices, udid)
            if refreshed is not None:
                print("Apple reported this device was already registered.")
                summarize_device_status(refreshed, team, show_raw=args.raw)
                return 0
            already_registered_patterns = (
                "already registered",
                "already exists",
                "already been registered",
                "device is registered",
                "device already",
            )
            if any(pattern in apple_message.lower() for pattern in already_registered_patterns):
                print(f"Apple reported this device is already registered, but listDevices did not return it yet: {apple_message}")
                return 0
            raise FlowError(
                "Apple rejected the device registration with result code 35. "
                f"That usually means the UDID or device name is invalid. Apple message: {apple_message}"
            ) from exc
        raise
    print("Apple accepted the add-device request.")

    refreshed_devices = client.fetch_devices(team_id, session)
    refreshed = find_device(refreshed_devices, udid) or added
    summarize_device_status(refreshed, team, show_raw=args.raw)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nCancelled.")
        raise SystemExit(130)
    except Exception as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
