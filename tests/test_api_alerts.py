"""Tests for the FastAPI alert endpoints."""

from fastapi.testclient import TestClient
from app.api.main import app

client = TestClient(app)

def test_health():
    """Health endpoint returns a successful status."""

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_get_alerts():
    """Alerts endpoint returns a list of alerts."""

    response = client.get("/alerts")

    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_alerts_with_filters():
    """Alerts endpoint accepts filtering and pagination parameters."""

    response = client.get(
        "/alerts/",
        params={
            "rule_id": "excessive_sudo",
            "technique_id": "T1548.003",
            "limit": 2,
            "offset": 0,
        },
    )

    assert response.status_code == 200

    alerts = response.json()

    assert isinstance(alerts, list)

    for alert in alerts:
        assert alert["rule_id"] == "excessive_sudo"
        assert alert["technique_id"] == "T1548.003"

def test_get_alerts_with_invalid_filters():
    """Alerts endpoint filters alerts from given start date."""

    response = client.get(
        "/alerts/",
        params={"start_date": "2026-03-27"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_alerts_with_end_date():

    """Alerts endpoint filters alerts up to the given end date."""

    response = client.get(
        "/alerts/",
        params={"end_date": "2026-03-27"},
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_alert_by_id():
    """Alert detail endpoint returns an existing alert."""

    response = client.get("/alerts/1")

    assert response.status_code == 200

    alert = response.json()

    assert alert["id"] == 1
    assert alert["rule_id"] == "excessive_sudo"
    assert alert["technique_id"] == "T1548.003"

def test_get_alert_by_id_not_found():
    """Alert detail endpoint returns 404 for an unknown ID."""

    response = client.get("/alerts/999999999")

    assert response.status_code == 404
    assert response.json() == {"detail": "Alert not found"}

def test_get_statu():
    """Stats endpoint returns all three alert groupings."""

    response = client.get("/stats")

    assert response.status_code == 200

    stats = response.json()

    assert "by_rule" in stats
    assert "by_technique" in stats

    assert isinstance(stats["by_rule"], dict)
    assert isinstance(stats["by_technique"], dict)
    assert isinstance(stats["by_tactic"], dict)

def test_app_lifespan():
    """Application lifespan initializes the database."""

    with TestClient(app) as client:
        response = client.get("/health")


    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
