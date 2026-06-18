"""Parser registry: map a :class:`SourceType` to the parser that handles it."""

from app.ingest.parsers.access_log import AccessLogParser
from app.ingest.parsers.auth_log import AuthLogParser
from app.ingest.parsers.base import LogParser, ParsedEvent
from app.ingest.parsers.suricata import SuricataParser
from app.models.enums import SourceType

_REGISTRY: dict[SourceType, type[LogParser]] = {
    SourceType.auth_log: AuthLogParser,
    SourceType.nginx: AccessLogParser,
    SourceType.apache: AccessLogParser,  # shares the NCSA combined format
    SourceType.suricata: SuricataParser,
}

SUPPORTED_SOURCE_TYPES = tuple(_REGISTRY)


def get_parser(source_type: SourceType) -> LogParser:
    """Instantiate the parser for ``source_type``.

    Raises :class:`ValueError` for source types without a parser yet (e.g.
    ``custom``), so the API can surface a clear 422 instead of failing deep
    in the ingest pipeline.
    """
    try:
        parser_cls = _REGISTRY[source_type]
    except KeyError:
        supported = ", ".join(sorted(s.value for s in _REGISTRY))
        raise ValueError(
            f"No parser for source type '{source_type}'. Supported: {supported}."
        ) from None
    return parser_cls()


__all__ = [
    "AccessLogParser",
    "AuthLogParser",
    "LogParser",
    "ParsedEvent",
    "SuricataParser",
    "SUPPORTED_SOURCE_TYPES",
    "get_parser",
]
