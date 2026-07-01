"""Unit tests for the format-agnostic GenericParser."""

from datetime import UTC, datetime

from app.ingest.parsers.generic import GenericParser

parser = GenericParser()


def test_parses_arbitrary_json_by_field_aliases() -> None:
    line = '{"client_ip":"203.0.113.9","dst_port":"22","proto":"TCP","status":401}'
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "203.0.113.9"
    assert event.protocol == "tcp"
    assert event.raw["dest_port"] == 22  # coerced to int
    assert event.raw["status"] == 401


def test_flattens_nested_json() -> None:
    line = (
        '{"source":{"ip":"198.51.100.5"},"destination":{"port":3389},"event":{"outcome":"failure"}}'
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "198.51.100.5"
    assert event.raw["dest_port"] == 3389
    assert event.raw["outcome"] == "failure"


def test_parses_logfmt_pairs() -> None:
    line = 'level=warning src=203.0.113.50 user=admin msg="login failed" proto=ssh'
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "203.0.113.50"
    assert event.protocol == "ssh"
    assert event.raw["username"] == "admin"


def test_extracts_ip_and_outcome_from_free_text() -> None:
    line = (
        "2026-06-10T06:11:01Z host sshd: authentication failure "
        "for root from 198.51.100.77 port 50001"
    )
    event = parser.parse_line(line)
    assert event is not None
    assert event.source_ip == "198.51.100.77"
    assert event.protocol == "ssh"
    assert event.raw["outcome"] == "failed"
    assert event.timestamp == datetime(2026, 6, 10, 6, 11, 1, tzinfo=UTC)


def test_extracts_http_request_from_free_text() -> None:
    line = '10.0.0.9 "GET /admin?id=1 HTTP/1.1" 403'
    event = parser.parse_line(line)
    assert event is not None
    assert event.protocol == "http"
    assert event.raw["method"] == "GET"
    assert event.raw["path"] == "/admin?id=1"
    assert event.raw["status"] == 403


def test_never_drops_a_line() -> None:
    event = parser.parse_line("totally opaque message with no useful fields")
    assert event is not None
    assert event.source_ip is None
    assert event.raw["message"] == "totally opaque message with no useful fields"


def test_timestampless_line_is_stamped_now() -> None:
    before = datetime.now(UTC)
    event = parser.parse_line("something happened to 10.0.0.1")
    assert event is not None
    assert event.timestamp >= before


def test_from_to_directionality() -> None:
    event = parser.parse_line("connection from 203.0.113.1 to 10.0.0.5 blocked")
    assert event is not None
    assert event.source_ip == "203.0.113.1"
    assert event.dest_ip == "10.0.0.5"


def test_invalid_ip_octets_are_ignored() -> None:
    event = parser.parse_line("version 999.1.1.1 released")
    assert event is not None
    assert event.source_ip is None
