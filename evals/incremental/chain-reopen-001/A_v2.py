"""A.py — entry points for the report endpoint, v2.

Two callers reach the report query:

* ``handle_request`` is the HTTP route. It coerces the filter to a list of
  integers before use.
* ``run_import`` is the batch import path. **It no longer coerces the filter**
  in v2: the validation was removed in the simulated diff. This is the change
  the incremental audit is run against.

On its own this file is a missing validation with no dangerous sink: all it can
do with the value is pass it on. Whether that matters depends on what the far
side does with it (see B.py).
"""

MAX_FILTER_LEN = 500


def handle_request(request, db):
    """Validated route. The coercion here is what makes the import path's
    absence of it (in this revision) a discrepancy rather than a vulnerability
    in itself."""
    filters = coerce_int_list(request.get("author_exclude"))
    return db.report(filters)


def run_import(request, db):
    """Batch import path, v2 — no longer coerces the filter. The caller-supplied
    value is forwarded unchanged, which is the discrepancy the v1 audit could
    not see."""
    filters = request.get("author_exclude")
    return db.report(filters)


def coerce_int_list(value):
    """Best-effort coercion to a list of integers."""
    if value is None:
        return []
    if isinstance(value, list):
        return [int(v) for v in value]
    return [int(value)]