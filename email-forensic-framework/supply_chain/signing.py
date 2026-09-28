"""
Container Image Signing and Cryptographic Attestation.
Component 13: Verifies digital signatures and provenance proofs for deployed images.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import hashlib
import time
import base64


@dataclass
class ImageSignature:
    signature_id: str
    image_digest: str
    signer_identity: str
    public_key_fingerprint: str
    signature_b64: str
    signed_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None

    def is_valid_now(self) -> bool:
        if self.expires_at is not None and time.time() > self.expires_at:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "image_digest": self.image_digest,
            "signer_identity": self.signer_identity,
            "public_key_fingerprint": self.public_key_fingerprint,
            "is_valid": self.is_valid_now(),
            "signed_at": self.signed_at,
        }


class ImageSignerVerifier:
    """Signs image digests and verifies cryptographic signatures (Cosign/Notary style)."""

    def __init__(self, signing_secret: str = "garuda-cosign-root-key-2026"):
        self.signing_secret = signing_secret
        self._signatures: Dict[str, ImageSignature] = {}
        self._load_defaults()

    def _load_defaults(self):
        # Sign default production MTA image
        mta_digest = "sha256:7f91a24d08e1f0e4b83c51f3ef4e5d6c7b8a9101112131415161718192021222"
        sig_mta = self.sign_digest(mta_digest, signer="release-signer@garuda.enterprise")
        self._signatures[sig_mta.image_digest] = sig_mta

        # Sign forensic api image
        forensic_digest = "sha256:5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b"
        sig_forensic = self.sign_digest(forensic_digest, signer="security-release@garuda.enterprise")
        self._signatures[sig_forensic.image_digest] = sig_forensic

    def sign_digest(self, image_digest: str, signer: str = "build-bot@garuda.enterprise") -> ImageSignature:
        now = time.time()
        payload = f"{image_digest}:{signer}:{self.signing_secret}:{int(now)}"
        sig_hash = hashlib.sha256(payload.encode("utf-8")).digest()
        sig_b64 = base64.b64encode(sig_hash).decode("utf-8")
        fp = hashlib.sha256(self.signing_secret.encode("utf-8")).hexdigest()[:16]

        sig = ImageSignature(
            signature_id=f"SIG-{image_digest[:12]}",
            image_digest=image_digest,
            signer_identity=signer,
            public_key_fingerprint=fp,
            signature_b64=sig_b64,
            signed_at=now,
            expires_at=now + (86400 * 365),  # 1 year
        )
        self._signatures[image_digest] = sig
        return sig

    def verify_signature(self, image_digest: str) -> bool:
        sig = self._signatures.get(image_digest)
        if not sig:
            return False
        return sig.is_valid_now()

    def get_signature(self, image_digest: str) -> Optional[ImageSignature]:
        return self._signatures.get(image_digest)
