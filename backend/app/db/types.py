"""Cross-dialect column types.

The data model stores rich, schema-less payloads (raw log lines, rule
definitions) as JSON. PostgreSQL gets binary ``JSONB`` for indexing and fast
containment queries; everything else (e.g. the SQLite database used by the
test-suite) falls back to the generic ``JSON`` type. Using one alias keeps the
models dialect-agnostic.
"""

from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import JSONB

# JSONB on PostgreSQL, generic JSON elsewhere.
JSONType = JSONB().with_variant(JSON(), "sqlite")
