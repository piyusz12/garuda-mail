from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import hashes
from typing import List, Optional

from app.models.tls_metadata import X509Certificate

class X509Parser:
    @staticmethod
    def parse_der(cert_bytes: bytes) -> Optional[X509Certificate]:
        try:
            cert = x509.load_der_x509_certificate(cert_bytes)
            
            # Subject and Issuer
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            
            # SANs
            san_list = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    # e.g., DNSName, IPAddress
                    san_list.append(name.value)
            except x509.ExtensionNotFound:
                pass
                
            # Key Info
            public_key = cert.public_key()
            pk_algo = "UNKNOWN"
            pk_size = 0
            
            if isinstance(public_key, rsa.RSAPublicKey):
                pk_algo = "RSA"
                pk_size = public_key.key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                pk_algo = "ECDSA"
                pk_size = public_key.curve.key_size
            elif isinstance(public_key, dsa.DSAPublicKey):
                pk_algo = "DSA"
                pk_size = public_key.key_size
                
            # Signature Algo
            sig_algo = cert.signature_algorithm_oid._name if cert.signature_algorithm_oid._name else "UNKNOWN"
            
            # Expiry
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            
            return X509Certificate(
                subject=subject,
                issuer=issuer,
                subject_alt_names=san_list,
                not_before=cert.not_valid_before_utc.replace(tzinfo=None),
                not_after=cert.not_valid_after_utc.replace(tzinfo=None),
                is_expired=now > cert.not_valid_after_utc.replace(tzinfo=None),
                public_key_algorithm=pk_algo,
                public_key_size=pk_size,
                signature_algorithm=sig_algo,
                serial_number=hex(cert.serial_number)[2:].upper()
            )
            
        except Exception as e:
            from app.logger import logger
            logger.error("X509_PARSE_ERROR", error=str(e))
            return None
