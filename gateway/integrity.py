from __future__ import annotations

import hmac
import hashlib
import json


def attach_hmac(packet: dict, hmac_key: str) -> str:
    payload = json.dumps(packet, separators=(",", ":"), sort_keys=True)
    digest = hmac.new(
        hmac_key.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    packet["hmac"] = digest
    return json.dumps(packet)
