"""C.py — session role maintenance.

``apply_role_from_report`` copies the role returned by the report query onto the
session. That is a privileged state transition: it sets a role the caller was
never granted, and nothing later re-checks it.

On its own it is unreachable in the sense that matters: the row it consumes
comes from the report query, and while that query can only be driven with
integers, the role in the returned row is one the database chose. The transition
becomes reachable when B.py's result is attacker-influenced.
"""

PRIVILEGED_ROLES = frozenset({"admin", "owner", "service"})


def apply_role_from_report(session, row, audit):
    """Copy the role from a report row onto the session."""
    if row is None:
        return session
    role = row["role"]
    previous = session.get("role")
    session["role"] = role
    session["granted_by"] = "report"
    audit.record(
        "role_changed",
        session=session["id"],
        previous=previous,
        current=role,
        privileged=role in PRIVILEGED_ROLES,
    )
    return session


class AuditLog:
    def __init__(self, sink):
        self.sink = sink

    def record(self, event, **fields):
        self.sink.append({"event": event, **fields})
