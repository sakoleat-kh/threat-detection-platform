"""Tests for the log ingestion API."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import app


client = TestClient(app)

AUTH_LOG = Path("data/sample_logs/auth_sample.log")
ACCESS_LOG = Path("data/sample_logs/access_sample.log")


def test_ingest_auth_log():
    """Valid auth log produces the expected alert count."""

    with AUTH_LOG.open("rb") as file:
        response = client.post(
            "/ingest/",
            files={
                "file": (
                    "auth_sample.log",
                    file,
                    "text/plain",
                )
            },
            data={"log_type": "auth"},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["lines_processed"] == 200
    assert data["alerts_generated"] == 1


def test_ingest_access_log():
    """Valid access log produces the expected alert count."""

    with ACCESS_LOG.open("rb") as file:
        response = client.post(
            "/ingest/",
            files={
                "file": (
                    "access_sample.log",
                    file,
                    "text/plain",
                )
            },
            data={"log_type": "access"},
        )

    assert response.status_code == 200

    data = response.json()

    assert data["lines_processed"] == 200
    assert data["alerts_generated"] == 0


def test_ingest_invalid_log_type():
    """Invalid log type returns HTTP 400."""

    response = client.post(
        "/ingest/",
        files={
            "file": (
                "test.log",
                b"some log content\n",
                "text/plain",
            )
        },
        data={"log_type": "invalid"},
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": "log_type must be 'auth' or 'access'"
    }


def test_ingest_empty_file():
    """An empty log file is handled without an error."""

    response = client.post(
        "/ingest/",
        files={
            "file": (
                "empty.log",
                b"",
                "text/plain",
            )
        },
        data={"log_type": "auth"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["lines_processed"] == 0
    assert data["alerts_generated"] == 0