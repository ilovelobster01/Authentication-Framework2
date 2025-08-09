from urllib.parse import quote
from app.cert_utils import parse_escaped_pem_cert, sha256_fingerprint
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
import datetime


def make_self_signed_cert(common_name='test-user'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TestOrg"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    return pem, cert


def test_parse_escaped_pem_cert_roundtrip():
    pem, cert = make_self_signed_cert()
    escaped = quote(pem.replace('\n', '\t'))
    parsed = parse_escaped_pem_cert(escaped)
    assert parsed is not None
    assert sha256_fingerprint(parsed) == cert.fingerprint(hashes.SHA256()).hex().upper()
