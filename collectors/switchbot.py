"""
SwitchBot cloud API collector.

Fetches temperature/humidity/battery from SwitchBot Meter devices via the
official cloud API (api.switch-bot.com v1.1).

Authentication: HMAC-SHA256 signature — token + secret from the SwitchBot app
(Profile → Preferences → App Version, tap the logo 10 times to reveal).
"""

import hashlib
import hmac
import logging
import time
import uuid
import base64

import requests

logger = logging.getLogger(__name__)

API_BASE = "https://api.switch-bot.com/v1.1"

# Device types known to report temperature in their status
TEMP_DEVICE_TYPES = {
    "Meter", "MeterPlus", "WoIOSensor", "Hub 2", "CO2 Sensor",
    "Meter Pro", "Meter Pro CO2",
}


class SwitchBotCollector:
    def __init__(self, config: dict):
        self.token   = config["token"]
        self.secret  = config["secret"]
        self.timeout = int(config.get("timeout", 10))

    def _auth_headers(self) -> dict:
        t     = str(int(time.time() * 1000))
        nonce = str(uuid.uuid4())
        msg   = f"{self.token}{t}{nonce}".encode("utf-8")
        sign  = base64.b64encode(
            hmac.new(self.secret.encode("utf-8"), msg, digestmod=hashlib.sha256).digest()
        ).decode()
        return {
            "Authorization": self.token,
            "sign":          sign,
            "nonce":         nonce,
            "t":             t,
            "Content-Type":  "application/json",
        }

    def _get(self, path: str) -> dict:
        r = requests.get(
            f"{API_BASE}{path}",
            headers=self._auth_headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("statusCode") != 100:
            raise RuntimeError(f"SwitchBot API error {data.get('statusCode')}: {data.get('message')}")
        return data["body"]

    def collect(self) -> dict:
        logger.info("SwitchBot: fetching device list")
        body = self._get("/devices")

        all_devices = body.get("deviceList", []) + body.get("infraredRemoteList", [])
        temp_devices = [d for d in all_devices if d.get("deviceType") in TEMP_DEVICE_TYPES]
        logger.info("SwitchBot: %d total devices, %d with temperature", len(all_devices), len(temp_devices))

        sensors = []
        for dev in temp_devices:
            device_id   = dev["deviceId"]
            device_name = dev.get("deviceName", device_id)
            device_type = dev.get("deviceType", "")
            try:
                status = self._get(f"/devices/{device_id}/status")
                entry = {
                    "id":          device_id,
                    "name":        device_name,
                    "type":        device_type,
                    "temperature": status.get("temperature"),
                    "humidity":    status.get("humidity"),
                    "battery":     status.get("battery"),
                    "co2":         status.get("CO2"),
                    "error":       None,
                }
                logger.debug(
                    "SwitchBot: %s → %.1f°C %s%%RH bat:%s%%",
                    device_name,
                    entry["temperature"] or 0,
                    entry["humidity"] or "-",
                    entry["battery"] or "-",
                )
            except Exception as exc:
                logger.warning("SwitchBot: %s status failed — %s", device_name, exc)
                entry = {
                    "id": device_id, "name": device_name, "type": device_type,
                    "temperature": None, "humidity": None, "battery": None,
                    "co2": None, "error": str(exc)[:200],
                }
            sensors.append(entry)

        return {"sensors": sensors}
