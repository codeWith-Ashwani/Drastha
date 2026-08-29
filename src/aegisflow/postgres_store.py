from __future__ import annotations

from typing import Any

from aegisflow.api_store import IncidentRepository, SCHEMA


class _PostgresConnection:
    def __init__(self, database_url: str) -> None:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("PostgreSQL mode requires the 'api' dependency group") from exc
        self._connection = psycopg.connect(database_url, row_factory=dict_row)

    def __enter__(self) -> "_PostgresConnection":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc_type is None:
            self._connection.commit()
        else:
            self._connection.rollback()
        self._connection.close()

    def execute(self, query: str, parameters: Any = ()) -> Any:
        return self._connection.execute(query.replace("?", "%s"), parameters)

    def executescript(self, script: str) -> None:
        for statement in script.split(";"):
            if statement.strip():
                self._connection.execute(statement)


class PostgreSQLIncidentRepository(IncidentRepository):
    """Production repository using the same inspectable schema as local SQLite."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self.initialize()

    def _connect(self) -> _PostgresConnection:
        return _PostgresConnection(self.database_url)

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(SCHEMA)
