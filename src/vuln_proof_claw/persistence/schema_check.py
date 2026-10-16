"""Compare a live database against the models the running code expects.

An agent meant to run unattended for days will be upgraded while its databases
persist, and a database made by one version is read by the next. When a column has
been added in between, nothing notices until a write reaches it -- and then every
cycle fails with ``table tasks has no column named sequence``, which is a sentence
about SQLite rather than about what the operator should do.

Observed exactly that way: three engagement databases predated a migration, and the
mission loop reported four consecutive cycle failures before stopping, with no hint
that the cause was the file rather than the target.

``Base.metadata`` is only populated by importing the models, which is why this
module imports them for their side effect: a check that silently compares against
an empty metadata reports every database as current, which is the one answer it
must never give by accident.

Only additive drift is reported, because that is the drift a release causes: tables
and columns the models have and the database does not. A column the database has and
the models do not is harmless and left alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Engine, inspect, text

from vuln_proof_claw.persistence import models as _models  # noqa: F401 - registers tables
from vuln_proof_claw.persistence.base import Base


@dataclass(frozen=True, slots=True)
class SchemaDrift:
    """What the models expect that the database does not have."""

    missing_tables: tuple[str, ...] = ()
    missing_columns: tuple[tuple[str, str], ...] = ()

    @property
    def current(self) -> bool:
        return not self.missing_tables and not self.missing_columns

    def describe(self) -> str:
        """Say what is missing, in the order an operator would want to read it."""
        if self.current:
            return "schema matches the models"
        parts: list[str] = []
        if self.missing_tables:
            parts.append(f"missing table(s): {', '.join(self.missing_tables)}")
        if self.missing_columns:
            columns = ", ".join(f"{table}.{column}" for table, column in self.missing_columns)
            parts.append(f"missing column(s): {columns}")
        return "; ".join(parts)


def inspect_schema(engine: Engine) -> SchemaDrift:
    """Return what the models expect that this database does not provide."""
    inspector = inspect(engine)
    present = set(inspector.get_table_names())

    missing_tables: list[str] = []
    missing_columns: list[tuple[str, str]] = []
    for name, table in Base.metadata.tables.items():
        if name not in present:
            missing_tables.append(name)
            continue
        existing = {column["name"] for column in inspector.get_columns(name)}
        missing_columns.extend(
            (name, column.name) for column in table.columns if column.name not in existing
        )

    return SchemaDrift(
        missing_tables=tuple(sorted(missing_tables)),
        missing_columns=tuple(sorted(missing_columns)),
    )


__all__ = ["SchemaDrift", "inspect_schema", "repair_schema"]


def _default_literal(server_default: object) -> str | None:
    """Return a column's server default as SQL, or None when it is not a plain literal.

    A default computed by the server -- a sequence, a function call -- cannot simply be
    repeated into an ALTER TABLE, and writing one that only looks right is worse than
    saying so.
    """
    argument = getattr(server_default, "arg", None)
    if argument is None:
        return None
    return str(getattr(argument, "text", argument))


def repair_schema(
    engine: Engine,
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...], tuple[tuple[str, str, str], ...]]:
    """Add the missing tables and columns, and report what could not be added.

    Additive and only additive. Missing tables are created from the models; missing
    columns are added with ``ALTER TABLE ... ADD COLUMN``. No column is dropped, no
    row is read, and no row is written -- a database holding evidence is a record of
    what was sent to somebody else's system, and bringing its schema forward must not
    be able to change what it says about that.

    A column that cannot be added in place is reported rather than forced. SQLite will
    not add a NOT NULL column without a default to a table that already has rows, and
    the honest answer there is to say so: silently making it nullable would leave the
    database disagreeing with the models in a way nothing would catch again.
    """
    drift = inspect_schema(engine)
    if drift.current:
        return ((), (), ())

    if drift.missing_tables:
        Base.metadata.create_all(
            engine, tables=[Base.metadata.tables[name] for name in drift.missing_tables]
        )

    added: list[tuple[str, str]] = []
    refused: list[tuple[str, str, str]] = []
    dialect = engine.dialect
    with engine.begin() as connection:
        for table_name, column_name in drift.missing_columns:
            column = Base.metadata.tables[table_name].columns[column_name]
            if not column.nullable and column.server_default is None:
                refused.append(
                    (
                        table_name,
                        column_name,
                        "NOT NULL with no server default; needs a migration that can "
                        "say what existing rows should hold",
                    )
                )
                continue
            default = _default_literal(column.server_default)
            if not column.nullable and default is None:
                refused.append(
                    (table_name, column_name, "default is not a literal this can repeat")
                )
                continue
            specification = f"{column.name} {column.type.compile(dialect)}"
            if not column.nullable:
                specification += " NOT NULL"
            if default is not None:
                specification += f" DEFAULT {default}"
            connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {specification}"))
            added.append((table_name, column_name))

    return (drift.missing_tables, tuple(added), tuple(refused))
