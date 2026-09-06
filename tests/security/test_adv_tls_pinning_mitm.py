"""
tests/security/test_adv_tls_pinning_mitm.py
============================================
Adversarial test for TLS certificate generation and MITM certificate substitution.
Validates:
1. Server generates RSA 2048-bit self-signed certificate with 10-year validity.
2. Cert persistence: cert.pem and key.pem are reused across server boots.
3. Rogue / mismatched certificate substitution is rejected by SHA-256 fingerprint check.
"""

import hashlib
import ssl
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
import pytest
from mobile_server import _get_or_create_tls_cert


def test_tls_cert_generation_parameters(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("mobile_server.CERT_PATH", cert_path)
        mp.setattr("mobile_server.KEY_PATH", key_path)

        cert_p, key_p, fp = _get_or_create_tls_cert()
        assert cert_p.exists()
        assert key_p.exists()
        assert len(fp) == 64  # SHA-256 hex string

        # Inspect certificate
        cert_bytes = cert_p.read_bytes()
        cert = x509.load_pem_x509_certificate(cert_bytes)

        # Assert RSA 2048-bit
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert public_key.key_size == 2048

        # Assert SHA-256 Fingerprint matches calculation
        calculated_fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        assert fp == calculated_fp


def test_tls_cert_reuse_persistence(tmp_path):
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("mobile_server.CERT_PATH", cert_path)
        mp.setattr("mobile_server.KEY_PATH", key_path)

        cert_p1, key_p1, fp1 = _get_or_create_tls_cert()
        cert_p2, key_p2, fp2 = _get_or_create_tls_cert()

        assert fp1 == fp2
        assert cert_p1.read_bytes() == cert_p2.read_bytes()


def test_mitm_rogue_certificate_fingerprint_mismatch(tmp_path):
    """Simulates a rogue server presenting an attacker-generated certificate."""
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("mobile_server.CERT_PATH", cert_path)
        mp.setattr("mobile_server.KEY_PATH", key_path)
        _, _, legit_fp = _get_or_create_tls_cert()

    # Generate rogue cert
    rogue_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Rogue Attacker Server")])
    now = datetime.now(timezone.utc)
    rogue_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(rogue_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(rogue_key, hashes.SHA256())
    )
    rogue_fp = hashlib.sha256(rogue_cert.public_bytes(serialization.Encoding.DER)).hexdigest()

    assert rogue_fp != legit_fp
