from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from rsb.agent.config import AgentConfig, hash_password
from rsb.agent.runtime import AgentRuntime
from rsb.agent.ui import create_ui_app
from rsb.config import Settings

TOKEN = "panel-token"
PASSWORD = "host-password"


def _runtime(tmp_path: Path) -> AgentRuntime:
    settings = Settings(
        data_dir=tmp_path,
        secret_key="ui-test-secret-key-material-0123456789",
        admin_ids="100",
        public_url="ws://127.0.0.1:1",
    )
    config = AgentConfig(
        device_id="device-id",
        device_secret="device-secret",
        relay_url="ws://127.0.0.1:1",
        name="test-pc",
        ui_port=8765,
        ui_token=TOKEN,
        password_hash=hash_password(PASSWORD),
    )
    return AgentRuntime(settings, config, tmp_path / "agent.json")


def _headers() -> dict[str, str]:
    return {"X-RSB-UI-Token": TOKEN}


def test_panel_requires_token(tmp_path: Path) -> None:
    client = TestClient(create_ui_app(_runtime(tmp_path)))
    assert client.get("/").status_code == 200
    assert client.get("/api/state").status_code == 401
    assert client.get(f"/?token={TOKEN}").status_code == 200
    assert client.get("/api/state", headers=_headers()).status_code == 200
    headers = client.get("/").headers
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"


def test_panel_lock_and_unlock(tmp_path: Path) -> None:
    client = TestClient(create_ui_app(_runtime(tmp_path)))
    state = client.get("/api/state", headers=_headers()).json()
    assert state["locked"] is True
    assert state["device"]["name"] == "test-pc"

    wrong = client.post("/api/unlock", json={"password": "wrong-password"}, headers=_headers())
    assert wrong.status_code == 401
    assert client.get("/api/state", headers=_headers()).json()["locked"] is True

    accepted = client.post("/api/unlock", json={"password": PASSWORD}, headers=_headers())
    assert accepted.status_code == 200
    assert client.get("/api/state", headers=_headers()).json()["locked"] is False

    locked = client.post("/api/lock", headers=_headers())
    assert locked.status_code == 200
    assert client.get("/api/state", headers=_headers()).json()["locked"] is True


def test_locked_panel_cannot_approve(tmp_path: Path) -> None:
    client = TestClient(create_ui_app(_runtime(tmp_path)))
    response = client.post(
        "/api/sessions/unknown/decision",
        json={"approved": True, "capabilities": ["shell"]},
        headers=_headers(),
    )
    assert response.status_code == 423
