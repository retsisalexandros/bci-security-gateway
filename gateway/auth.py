from __future__ import annotations

import ssl
import logging
from cryptography import x509

logger = logging.getLogger(__name__)


def build_ssl_context(
    server_cert: str,
    server_key: str,
    ca_cert: str,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
    ctx.load_verify_locations(cafile=ca_cert)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def extract_device_id(ssl_object: ssl.SSLObject | ssl.SSLSocket) -> str | None:
    peer_cert_der = ssl_object.getpeercert(binary_form=True)
    if peer_cert_der is None:
        return None
    cert = x509.load_der_x509_certificate(peer_cert_der)
    cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if not cn_attrs:
        return None
    return cn_attrs[0].value


def check_allowlist(device_id: str, allowlist: list[str]) -> bool:
    return device_id in allowlist
