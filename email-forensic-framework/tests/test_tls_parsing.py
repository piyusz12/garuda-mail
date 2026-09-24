import pytest
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from app.tls.ja4 import generate_ja4_client, generate_ja4_server
from app.tls.x509_parser import X509Parser

def test_ja4_client():
    # Example: TLS 1.2, 2 ciphers (0xc02b, 0xc02f), 3 extensions (0, 10, 11), with SNI
    # Version: 0x0303 -> '12'
    # SNI: 'd'
    # Ciphers count: 2 -> '02'
    # Exts count: 3 -> '03'
    # ja4_a should be "t12d0203"
    
    ja4 = generate_ja4_client(
        version=0x0303,
        ciphers=[0xc02b, 0xc02f],
        extensions=[0x0000, 0x000a, 0x000b],
        sni="example.com",
        alpn=["h2", "http/1.1"]
    )
    
    parts = ja4.split('_')
    assert len(parts) == 3
    assert parts[0] == "t12d0203"
    assert len(parts[1]) == 12 # Hash truncated to 12
    assert len(parts[2]) == 12

def test_x509_parser():
    # 1. Generate a self-signed cert
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Valid for 10 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    
    # 2. Parse using our implementation
    parsed = X509Parser.parse_der(der_bytes)
    
    assert parsed is not None
    assert "CN=localhost" in parsed.subject
    assert "CN=localhost" in parsed.issuer
    assert "localhost" in parsed.subject_alt_names
    assert parsed.public_key_algorithm == "RSA"
    assert parsed.public_key_size == 2048
    assert parsed.signature_algorithm == "sha256WithRSAEncryption"
    assert parsed.is_expired is False
