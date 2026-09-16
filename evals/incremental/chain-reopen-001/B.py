"""B.py — the report query builder.

``build_query`` concatenates the author filter into the SQL text. Reached only
through the validated route today, where the filter is already a list of
integers, so the concatenation cannot be driven from outside: every element it
can receive is an ``int``.

That is a real prerequisite, not a mitigation — the primitive itself is intact,
and it needs one caller that can put a string in that list. Recorded as blocked
rather than rejected for exactly that reason.
"""

SQL_TEMPLATE = "SELECT author_id, role FROM authored WHERE author_id IN (%s)"


def build_query(author_exclude):
    """The primitive: the filter is formatted into the statement.

    ``str()`` of an integer is harmless. ``str()`` of anything else is not, and
    nothing here establishes which one it is holding.
    """
    clause = ", ".join(str(value) for value in author_exclude)
    return SQL_TEMPLATE % clause


class ReportDb:
    """Minimal stand-in for the data layer, so the caller in A.py has something
    to call."""

    def __init__(self, connection):
        self.connection = connection

    def report(self, author_exclude):
        return self.connection.execute(build_query(author_exclude))