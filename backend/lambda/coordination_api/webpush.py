"""Web Push primitives for the coordination API (DVP-TSK-A23, E4-R29/R30).

Ported from the intelligence coach_push_sender: RFC 8291 aes128gcm payload
encryption, RFC 8292 VAPID (ES256) request signing, a stdlib HTTP sender and
a push-service host allow-list. The VAPID keypair is DERIVED (HKDF-SHA256)
from COORDINATION_INTERNAL_API_KEY with the label ``enceladus-vapid-v1`` so
no new secret exists; rotating that key rotates the keypair (subscriptions
re-register against the new public key on the next app open).
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VAPID_INFO = b"enceladus-vapid-v1"
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
HTTP_TIMEOUT = 10
MAX_ENDPOINT_LEN = 2048
# Push services only: the sender POSTs to whatever endpoint is stored, so the
# stored value is restricted to the known browser push services (no SSRF).
ALLOWED_PUSH_HOST_SUFFIXES = tuple(
    s.strip() for s in os.environ.get(
        "PUSH_ENDPOINT_HOST_SUFFIXES",
        "fcm.googleapis.com,push.services.mozilla.com,push.apple.com,notify.windows.com",
    ).split(",") if s.strip())


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def endpoint_allowed(endpoint):
    """True for an https URL (<= 2048 chars) on a known push-service host."""
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > MAX_ENDPOINT_LEN:
        return False
    try:
        parsed = urlparse(endpoint)
    except ValueError:
        return False
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return False
    return any(host == s or host.endswith("." + s) for s in ALLOWED_PUSH_HOST_SUFFIXES)


def derive_vapid(internal_key, subject=None):
    """Deterministic VAPID keypair from the coordination internal key (E4-R30)."""
    ikm = internal_key.encode("utf-8") if isinstance(internal_key, str) else bytes(internal_key or b"")
    if not ikm:
        raise ValueError("COORDINATION_INTERNAL_API_KEY is empty; cannot derive VAPID key")
    okm = HKDF(hashes.SHA256(), 32, None, VAPID_INFO).derive(ikm)
    order = _P256_ORDER
    scalar = int.from_bytes(okm, "big") % (order - 1) + 1
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return {"private": b64u(scalar.to_bytes(32, "big")), "public": b64u(public),
            "subject": subject or os.environ.get("VAPID_SUBJECT") or "https://jreese.net"}


def encrypt_aes128gcm(plaintext, p256dh_b64u, auth_b64u, *, salt=None, as_private=None):
    ua_public = b64u_decode(p256dh_b64u)
    auth_secret = b64u_decode(auth_b64u)
    as_private = as_private or ec.generate_private_key(ec.SECP256R1())
    as_public = as_private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    ecdh = as_private.exchange(ec.ECDH(), ua_key)
    ikm = HKDF(hashes.SHA256(), 32, auth_secret,
               b"WebPush: info\x00" + ua_public + as_public).derive(ecdh)
    salt = salt or os.urandom(16)
    cek = HKDF(hashes.SHA256(), 16, salt, b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(hashes.SHA256(), 12, salt, b"Content-Encoding: nonce\x00").derive(ikm)
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    return salt + (4096).to_bytes(4, "big") + bytes([len(as_public)]) + as_public + ciphertext


def vapid_headers(endpoint, vapid, now=None):
    """Authorization header for `endpoint` (RFC 8292 `vapid t=,k=` scheme)."""
    parsed = urlparse(endpoint)
    claims = {"aud": f"{parsed.scheme}://{parsed.netloc}",
              "exp": int(now or time.time()) + 12 * 3600,
              "sub": vapid.get("subject") or "https://jreese.net"}
    signing_input = (b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
                     + "." + b64u(json.dumps(claims, separators=(",", ":")).encode()))
    private = ec.derive_private_key(int.from_bytes(b64u_decode(vapid["private"]), "big"), ec.SECP256R1())
    r, s = decode_dss_signature(private.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256())))
    token = signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return {"Authorization": f"vapid t={token}, k={vapid['public']}"}


def http_send(endpoint, body, headers):
    """POST to the push service. Returns the HTTP status; network errors raise."""
    req = urllib.request.Request(endpoint, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
