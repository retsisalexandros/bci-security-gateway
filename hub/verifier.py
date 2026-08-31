from __future__ import annotations
import hmac
import hashlib
import json
import logging

logger = logging.getLogger(__name__)


def verify_and_strip(raw_message: str, hmac_key: str) -> str | None:
    try:
        data = json.loads(raw_message)
    except json.JSONDecodeError:
        logger.warning("Received non-JSON message, dropping.")
        return None

    received_hmac = data.pop("hmac", None)
    if received_hmac is None:
        logger.warning("Packet missing HMAC field, dropping.")
        return None

    payload = json.dumps(data, separators=(",", ":"), sort_keys=True)
    expected = hmac.new(
        hmac_key.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(received_hmac, expected):
        logger.warning(
            "HMAC mismatch for device %s seq %s, dropping packet.",
            data.get("device_id", "?"),
            data.get("seq", "?"),
        )
        return None

    return json.dumps(data)
