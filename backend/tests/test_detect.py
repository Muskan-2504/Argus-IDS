"""Unit tests for the log-format sniffer."""

from app.ingest.detect import sniff_source_type
from app.models.enums import SourceType

AUTH = (
    "Jun 10 06:11:01 web-01 sshd[20144]: Failed password for invalid user "
    "admin from 203.0.113.5 port 54001 ssh2"
)
ACCESS = (
    "198.51.100.23 - - [10/Jun/2026:06:03:48 +0000] "
    '"GET /index.html HTTP/1.1" 200 5123 "-" "curl/8"'
)
SURICATA = (
    '{"timestamp":"2026-06-10T06:05:01.000000+0000","event_type":"alert",'
    '"src_ip":"203.0.113.88","dest_ip":"10.0.0.10","dest_port":22,"proto":"TCP"}'
)


def test_sniffs_auth_log() -> None:
    assert sniff_source_type(AUTH) is SourceType.auth_log


def test_sniffs_access_log() -> None:
    assert sniff_source_type(ACCESS) is SourceType.nginx


def test_sniffs_suricata_eve_json() -> None:
    assert sniff_source_type(SURICATA) is SourceType.suricata


def test_skips_leading_blank_lines() -> None:
    assert sniff_source_type(f"\n   \n{AUTH}") is SourceType.auth_log


def test_returns_none_for_unrecognized_text() -> None:
    assert sniff_source_type("just some prose that is not a log at all") is None


def test_returns_none_for_empty_text() -> None:
    assert sniff_source_type("") is None
