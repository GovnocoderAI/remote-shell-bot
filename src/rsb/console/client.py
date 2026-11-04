from __future__ import annotations

from typing import Any

import httpx


class ConsoleAPIError(RuntimeError):
    pass


class ConsoleClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"X-RSB-Console-Token": token},
            timeout=150.0,
        )

    def close(self) -> None:
        self._client.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        raw: bool = False,
    ) -> Any:
        try:
            response = self._client.request(method, path, json=json, params=params)
        except httpx.HTTPError as exc:
            raise ConsoleAPIError(f"relay недоступен: {exc}") from exc
        if response.status_code >= 400:
            detail = response.text[:400]
            try:
                payload = response.json()
                detail = str(payload.get("detail", detail))
            except ValueError:
                pass
            raise ConsoleAPIError(f"HTTP {response.status_code}: {detail}")
        if raw:
            meta = {
                "width": response.headers.get("X-RSB-Width"),
                "height": response.headers.get("X-RSB-Height"),
                "taken_at": response.headers.get("X-RSB-Taken-At"),
            }
            return response.content, meta
        if "application/json" in response.headers.get("content-type", ""):
            return response.json()
        return response.content

    def overview(self) -> dict[str, Any]:
        return self._request("GET", "/api/console/overview")

    def devices(self) -> list[dict[str, Any]]:
        return list(self._request("GET", "/api/console/devices").get("devices", []))

    def request_session(
        self, device_id: str, capabilities: list[str], purpose: str = "console"
    ) -> dict[str, Any]:
        payload = self._request(
            "POST",
            "/api/console/sessions",
            json={
                "device_id": device_id,
                "capabilities": capabilities,
                "purpose": purpose,
            },
        )
        return payload["session"]

    def current_session(self) -> dict[str, Any]:
        return self._request("GET", "/api/console/sessions/current")

    def session(self, session_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/console/sessions/{session_id}")

    def command(self, session_id: str, command: str) -> dict[str, Any]:
        payload = self._request(
            "POST",
            f"/api/console/sessions/{session_id}/command",
            json={"command": command},
        )
        return payload["result"]

    def screenshot(self, session_id: str) -> tuple[bytes, dict[str, Any]]:
        return self._request("GET", f"/api/console/sessions/{session_id}/screenshot", raw=True)

    def close_session(self, session_id: str) -> dict[str, Any]:
        return self._request("POST", f"/api/console/sessions/{session_id}/close")

    def audit(self, limit: int = 20) -> list[dict[str, Any]]:
        payload = self._request("GET", "/api/console/audit", params={"limit": limit})
        return list(payload.get("audit", []))
