from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from rsb.config import Settings
from rsb.server.app import create_app


def _settings(tmp_path: Path, token: str = "console-secret-token") -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "relay.sqlite3",
        secret_key="console-test-secret-key-material-0123456789",
        admin_ids="100",
        public_url="ws://127.0.0.1:30000",
        bot_token="",
        console_token=token,
        console_operator_id=100,
    )


def test_console_api_requires_token(tmp_path) -> None:
    app = create_app(_settings(tmp_path))
    with TestClient(app) as client:
        assert client.get("/api/console/overview").status_code == 401
        assert (
            client.get(
                "/api/console/overview",
                headers={"X-RSB-Console-Token": "wrong"},
            ).status_code
            == 401
        )
        response = client.get(
            "/api/console/overview",
            headers={"X-RSB-Console-Token": "console-secret-token"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["operator"]["id"] == 100
        assert data["devices"] == []
        assert "stats" in data


def test_console_api_disabled_without_token(tmp_path) -> None:
    app = create_app(_settings(tmp_path, token=""))
    with TestClient(app) as client:
        response = client.get(
            "/api/console/overview",
            headers={"X-RSB-Console-Token": "anything"},
        )
        assert response.status_code == 404


def test_console_devices_and_audit(tmp_path) -> None:
    app = create_app(_settings(tmp_path))
    headers = {"X-RSB-Console-Token": "console-secret-token"}
    with TestClient(app) as client:
        devices = client.get("/api/console/devices", headers=headers)
        assert devices.status_code == 200
        assert devices.json()["devices"] == []
        audit = client.get("/api/console/audit", headers=headers)
        assert audit.status_code == 200
        assert isinstance(audit.json()["audit"], list)


def test_console_device_payload_has_no_secret() -> None:
    from rsb.server.app import _public_device

    device = _public_device(
        {"id": "x", "name": "pc", "secret_encrypted": "secret", "capabilities": []}
    )
    assert "secret_encrypted" not in device
    assert device["name"] == "pc"
