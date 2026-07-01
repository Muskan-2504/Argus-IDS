"""Unit tests for the log parsers and the parser registry."""

from pathlib import Path

import pytest

from app.ingest.parsers import get_parser
from app.ingest.parsers.access_log import AccessLogParser
from app.ingest.parsers.auth_log import AuthLogParser
from app.ingest.parsers.suricata import SuricataParser
from app.models.enums import SourceType

SAMPLES = Path(__file__).resolve().parents[2] / "data" / "samples"


# --- auth.log -------------------------------------------------------------


def test_auth_log_failed_password() -> None:
    parser = AuthLogParser(year=2024)
    event = parser.parse_line(
        "Oct 10 13:55:33 web01 sshd[2004]: Failed password for root "
        "from 203.0.113.5 port 54324 ssh2"
    )
    assert event is not None
    assert event.source_ip == "203.0.113.5"
    assert event.protocol == "ssh"
    assert event.raw == {
        "outcome": "failed",
        "username": "root",
        "source_port": 54324,
        "service": "sshd",
    }
    assert event.timestamp.year == 2024


def test_auth_log_invalid_user_outcome() -> None:
    parser = AuthLogParser(year=2024)
    event = parser.parse_line(
        "Oct 10 13:55:30 web01 sshd[2001]: Failed password for invalid user admin "
        "from 203.0.113.5 port 54321 ssh2"
    )
    assert event is not None
    assert event.raw["outcome"] == "invalid_user"
    assert event.raw["username"] == "admin"


def test_auth_log_accepted() -> None:
    parser = AuthLogParser(year=2024)
    event = parser.parse_line(
        "Oct 10 13:55:40 web01 sshd[2010]: Accepted password for alice "
        "from 10.0.0.5 port 53210 ssh2"
    )
    assert event is not None
    assert event.raw["outcome"] == "accepted"
    assert event.source_ip == "10.0.0.5"


def test_auth_log_ignores_non_ssh_lines() -> None:
    parser = AuthLogParser(year=2024)
    assert parser.parse_line("Oct 10 13:56:05 web01 sudo: pam_unix(sudo:session): opened") is None


# --- access log -----------------------------------------------------------


def test_access_log_combined() -> None:
    parser = AccessLogParser()
    event = parser.parse_line(
        '203.0.113.22 - - [10/Oct/2024:13:51:10 +0000] "GET /products?id=42 HTTP/1.1" '
        '404 153 "-" "sqlmap/1.5.2"'
    )
    assert event is not None
    assert event.source_ip == "203.0.113.22"
    assert event.protocol == "http"
    assert event.raw["method"] == "GET"
    assert event.raw["status"] == 404
    assert event.raw["user_agent"] == "sqlmap/1.5.2"


def test_access_log_dash_size_is_none() -> None:
    parser = AccessLogParser()
    event = parser.parse_line(
        '192.0.2.10 - - [10/Oct/2024:13:50:01 +0000] "GET / HTTP/1.1" 200 - "-" "curl/8"'
    )
    assert event is not None
    assert event.raw["size"] is None


# --- suricata -------------------------------------------------------------


def test_suricata_alert() -> None:
    parser = SuricataParser()
    event = parser.parse_line(
        '{"timestamp":"2024-10-10T13:58:00.100000+0000","event_type":"alert",'
        '"src_ip":"203.0.113.66","src_port":40000,"dest_ip":"10.0.0.5","dest_port":22,'
        '"proto":"TCP","alert":{"signature":"ET SCAN","signature_id":1,"severity":2}}'
    )
    assert event is not None
    assert event.source_ip == "203.0.113.66"
    assert event.dest_ip == "10.0.0.5"
    assert event.protocol == "tcp"
    assert event.raw["dest_port"] == 22
    assert event.raw["alert"]["signature"] == "ET SCAN"


def test_suricata_skips_non_json() -> None:
    assert SuricataParser().parse_line("this is not json") is None


# --- registry -------------------------------------------------------------


def test_registry_resolves_every_source_type() -> None:
    from app.ingest.parsers.base import LogParser

    for source_type in SourceType:
        assert isinstance(get_parser(source_type), LogParser)


def test_registry_unknown_source_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    # The defensive ValueError still guards a SourceType with no registered parser.
    from app.ingest import parsers

    monkeypatch.delitem(parsers._REGISTRY, SourceType.custom)
    with pytest.raises(ValueError, match="No parser"):
        get_parser(SourceType.custom)


@pytest.mark.parametrize(
    ("filename", "source_type"),
    [
        ("auth.log", SourceType.auth_log),
        ("nginx_access.log", SourceType.nginx),
        ("suricata_eve.json", SourceType.suricata),
    ],
)
def test_sample_files_parse(filename: str, source_type: SourceType) -> None:
    """The shipped sample logs must parse into at least one event each."""
    text = (SAMPLES / filename).read_text(encoding="utf-8")
    events = list(get_parser(source_type).parse(text))
    assert len(events) >= 1
    assert all(e.source_ip for e in events)
