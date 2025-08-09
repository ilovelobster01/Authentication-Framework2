from typing import Optional
from urllib.parse import unquote
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import binascii
import re


def _reconstruct_pem(s: str) -> Optional[str]:
    """
    Reconstruct a valid PEM block from a possibly mangled string that should contain
    -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE----- with arbitrary whitespace.
    - Accepts tabs or spaces in place of newlines.
    - Removes all whitespace inside the base64 payload and re-wraps to 64 chars per line.
    """
    begin_marker = "-----BEGIN CERTIFICATE-----"
    end_marker = "-----END CERTIFICATE-----"

    # Normalize CR and tabs to LF; leave spaces intact for now
    s = s.replace("\r", "").replace("\t", "\n")

    if begin_marker not in s or end_marker not in s:
        return None
    start = s.find(begin_marker)
    end = s.find(end_marker, start)
    if end == -1:
        return None

    # Extract inner base64 part, strip markers
    inner = s[start + len(begin_marker):end]
    # Remove all whitespace (spaces, newlines, tabs)
    inner_b64 = re.sub(r"\s+", "", inner)
    if not inner_b64:
        return None

    # Wrap at 64 chars
    wrapped = "\n".join(inner_b64[i:i+64] for i in range(0, len(inner_b64), 64))
    pem = f"{begin_marker}\n{wrapped}\n{end_marker}\n"
    return pem


def _try_parse_der_from_base64(s: str) -> Optional[x509.Certificate]:
    """
    Attempt to parse a certificate if the input appears to be a base64-encoded DER
    without PEM markers. We tolerate spaces, commas, and newlines.
    """
    # Remove surrounding quotes, commas, and whitespace
    cleaned = s.strip().strip('"').replace(',', '')
    cleaned = re.sub(r"\s+", "", cleaned)
    # Base64 charset check (allow padding '=')
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", cleaned or ""):  # empty guard
        return None
    # Require minimal length to avoid false positives
    if len(cleaned) < 100:
        return None
    try:
        der = base64.b64decode(cleaned, validate=False)
        if not der or len(der) < 200:
            return None
        return x509.load_der_x509_certificate(der, default_backend())
    except (binascii.Error, ValueError):
        return None


def parse_escaped_pem_cert(escaped: str) -> Optional[x509.Certificate]:
    try:
        if not escaped:
            return None
        # nginx $ssl_client_escaped_cert: URL-escaped, newlines replaced with '\t'. Some proxies may alter tabs/spaces.
        s = unquote(escaped)

        # 1) Try direct PEM (tabs -> newlines)
        direct = s.replace("\r", "").replace("\t", "\n")
        if "BEGIN CERTIFICATE" in direct and "END CERTIFICATE" in direct:
            try:
                return x509.load_pem_x509_certificate(direct.encode("utf-8"), default_backend())
            except Exception:
                pass

        # 2) Try robust PEM reconstruction
        pem = _reconstruct_pem(s)
        if pem:
            try:
                return x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
            except Exception:
                pass

        # 3) Try base64 DER fallback (no PEM markers)
        der_cert = _try_parse_der_from_base64(s)
        if der_cert:
            return der_cert

        # 4) Rare case: already raw PEM in header, unescaped
        if escaped.startswith("-----BEGIN") and escaped.strip().endswith("END CERTIFICATE-----"):
            try:
                return x509.load_pem_x509_certificate(escaped.encode("utf-8"), default_backend())
            except Exception:
                pass
        return None
    except Exception:
        return None


def sha256_fingerprint(cert: x509.Certificate) -> str:
    fp = cert.fingerprint(hashes.SHA256())
    return fp.hex().upper()
