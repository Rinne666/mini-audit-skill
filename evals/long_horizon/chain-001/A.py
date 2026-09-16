"""A.py — entry points for the report endpoint.

Two callers reach the report query:

* ``handle_request`` is the HTTP route. It coerces the filter to a list of
  integers before use.
* ``run_import`` is the batch import path. It forwards the caller-supplied
  value unchanged.

On its own this file is a missing validation with no dangerous sink: all it can
do with the value is pass it on. Whether that matters depends on what the far
side does with it (see B.py).
"""

MAX_FILTER_LEN = 500


def handle_request(request, db):
    """Validated route. The coercion here is what makes the import path's
    absence of it a discrepancy rather than a vulnerability in itself."""
    filters = coerce_int_list(request.get("author_exclude"))
    return db.report(filters)


def run_import(request, db):
    """Batch import path — reaches the same query without any coercion."""
    filters = request.get("author_exclude")
    return db.report(filters)


def coerce_int_list(value):
    """Element-wise integer coercion. Rejects rather than repairs, so a caller
    cannot smuggle a string through by making it look numeric."""
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [int(value)]
    if not isinstance(value, (list, tuple)):
        raise TypeError("author_exclude must be a list of integers")
    if len(value) > MAX_FILTER_LEN:
        raise ValueError("author_exclude is too long")
    out = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise TypeError("author_exclude must contain integers only")
        out.append(item)
    return out
