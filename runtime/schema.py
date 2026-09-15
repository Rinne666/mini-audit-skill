"""JSON Schema validation (Hardening v1.1 §5).

The runtime ships JSON Schemas in ``schemas/`` but v1 only used them as
documentation — validation was done by hand-written validators, which meant
two rule sets that could drift apart. Hardening v1.1 makes the schemas
authoritative: gates, ``finding validate``, ``coverage validate`` and
``state load`` all run the real schema.

To stay stdlib-only (the runtime has no third-party dependencies on
purpose), this module implements the JSON Schema *subset* the shipped
schemas actually use:

    type (string | list)
    enum, const
    required, properties, additionalProperties, minProperties, maxProperties
    items, minItems, maxItems, uniqueItems
    minLength, maxLength, pattern
    minimum, maximum, exclusiveMinimum, exclusiveMaximum
    allOf, anyOf, oneOf, not
    if / then / else
    $ref to "#" and "#/$defs/<name>"

Unsupported keywords are ignored rather than rejected, so a schema that
grows a new keyword degrades to "not checked here" instead of exploding.

When the optional ``jsonschema`` package *is* installed, callers may prefer
it; :func:`validate_instance` uses it when available and falls back to the
built-in validator otherwise. Both paths report the same error shape.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

try:  # optional accelerator / cross-check
    import jsonschema as _jsonschema  # type: ignore

    HAS_JSONSCHEMA = True
except Exception:  # pragma: no cover - optional dependency
    _jsonschema = None
    HAS_JSONSCHEMA = False


class SchemaError:
    """One validation error."""

    __slots__ = ("path", "message", "schema_path")

    def __init__(self, path: str, message: str, schema_path: str = "") -> None:
        self.path = path
        self.message = message
        self.schema_path = schema_path

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message, "schema_path": self.schema_path}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"SchemaError({self.path!r}, {self.message!r})"

    def __str__(self) -> str:
        return f"{self.path or '<root>'}: {self.message}"


class SchemaValidationError(ValueError):
    """Raised by :func:`validate_instance_raise` when validation fails."""

    def __init__(self, errors: Sequence[SchemaError], *, artifact: str = "") -> None:
        self.errors = list(errors)
        self.artifact = artifact
        where = f" in {artifact}" if artifact else ""
        detail = "; ".join(str(e) for e in self.errors[:5])
        more = f" (+{len(self.errors) - 5} more)" if len(self.errors) > 5 else ""
        super().__init__(f"schema validation failed{where}: {detail}{more}")


# ---------------------------------------------------------------------------
# Schema discovery
# ---------------------------------------------------------------------------


def resolve_schema_dir() -> Path:
    """Locate the ``schemas/`` directory shipped next to the runtime package."""
    override = os.environ.get("MINI_AUDIT_SCHEMA_DIR")
    if override:
        candidate = Path(override).resolve()
        if candidate.is_dir():
            return candidate
    # runtime/schema.py → parent is runtime/, parent.parent is the skill root.
    return Path(__file__).resolve().parent.parent / "schemas"


def schema_path(name: str) -> Path:
    """Return the on-disk path for schema *name* (``finding`` or ``finding.schema.json``)."""
    if not name.endswith(".json"):
        name = f"{name}.schema.json"
    return resolve_schema_dir() / name


def load_schema(name: str) -> dict[str, Any]:
    """Load a shipped JSON Schema by short name or filename."""
    path = schema_path(name)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_schema_or_none(name: str) -> Optional[dict[str, Any]]:
    try:
        return load_schema(name)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


_TYPE_MAP: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _json_type_ok(value: Any, expected: str) -> bool:
    if expected == "integer":
        # JSON Schema: 1.0 is an integer, True/False are not.
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected in _TYPE_MAP:
        return isinstance(value, _TYPE_MAP[expected])
    return True  # unknown type name — ignore


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


class _Validator:
    def __init__(self, root: Mapping[str, Any]) -> None:
        self.root = root
        self.errors: list[SchemaError] = []
        self._seen: set[tuple[int, str]] = set()

    # -- ref resolution ---------------------------------------------------
    def _resolve_ref(self, ref: str) -> Optional[Mapping[str, Any]]:
        if not ref.startswith("#"):
            return None  # external refs unsupported → ignore
        pointer = ref[1:]
        if pointer in ("", "/"):
            return self.root
        if not pointer.startswith("/"):
            return None
        node: Any = self.root
        for raw in pointer.lstrip("/").split("/"):
            token = raw.replace("~1", "/").replace("~0", "~")
            if isinstance(node, Mapping) and token in node:
                node = node[token]
            else:
                return None
        return node if isinstance(node, Mapping) else None

    # -- entry ------------------------------------------------------------
    def validate(self, instance: Any, schema: Mapping[str, Any], path: str = "") -> None:
        if not isinstance(schema, Mapping):
            return

        if "$ref" in schema:
            target = self._resolve_ref(str(schema["$ref"]))
            if target is not None:
                # Guard against self-referential loops on the same instance node.
                key = (id(instance), json.dumps(schema, sort_keys=True))
                if key in self._seen:
                    return
                self._seen.add(key)
                self.validate(instance, target, path)
                return

        self._check_type(instance, schema, path)
        self._check_enum_const(instance, schema, path)
        if isinstance(instance, str):
            self._check_string(instance, schema, path)
        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            self._check_number(instance, schema, path)
        if isinstance(instance, list):
            self._check_array(instance, schema, path)
        if isinstance(instance, dict):
            self._check_object(instance, schema, path)

        self._check_combinators(instance, schema, path)
        self._check_conditionals(instance, schema, path)

    # -- individual keyword groups ---------------------------------------
    def _check_type(self, instance: Any, schema: Mapping[str, Any], path: str) -> None:
        expected = schema.get("type")
        if expected is None:
            return
        names = [expected] if isinstance(expected, str) else list(expected)
        if not any(_json_type_ok(instance, n) for n in names):
            self.errors.append(
                SchemaError(path, f"expected type {names}, got {_type_name(instance)}")
            )

    def _check_enum_const(self, instance: Any, schema: Mapping[str, Any], path: str) -> None:
        if "const" in schema and instance != schema["const"]:
            self.errors.append(SchemaError(path, f"expected const {schema['const']!r}, got {instance!r}"))
        if "enum" in schema:
            allowed = schema["enum"]
            # JSON Schema equality, with the Python bool/int trap guarded:
            # True must not satisfy an enum of [1].
            ok = any(
                instance == a and isinstance(instance, bool) == isinstance(a, bool)
                for a in allowed
            )
            if not ok:
                self.errors.append(SchemaError(path, f"{instance!r} is not one of {allowed}"))

    def _check_string(self, instance: str, schema: Mapping[str, Any], path: str) -> None:
        if "minLength" in schema and len(instance) < int(schema["minLength"]):
            self.errors.append(SchemaError(path, f"string shorter than minLength {schema['minLength']}"))
        if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
            self.errors.append(SchemaError(path, f"string longer than maxLength {schema['maxLength']}"))
        if "pattern" in schema:
            try:
                if re.search(str(schema["pattern"]), instance) is None:
                    self.errors.append(SchemaError(path, f"{instance!r} does not match pattern {schema['pattern']!r}"))
            except re.error as exc:  # pragma: no cover - bad schema
                self.errors.append(SchemaError(path, f"invalid schema pattern {schema['pattern']!r}: {exc}"))

    def _check_number(self, instance: float, schema: Mapping[str, Any], path: str) -> None:
        if "minimum" in schema and instance < schema["minimum"]:
            self.errors.append(SchemaError(path, f"{instance} < minimum {schema['minimum']}"))
        if "maximum" in schema and instance > schema["maximum"]:
            self.errors.append(SchemaError(path, f"{instance} > maximum {schema['maximum']}"))
        if "exclusiveMinimum" in schema and instance <= schema["exclusiveMinimum"]:
            self.errors.append(SchemaError(path, f"{instance} <= exclusiveMinimum {schema['exclusiveMinimum']}"))
        if "exclusiveMaximum" in schema and instance >= schema["exclusiveMaximum"]:
            self.errors.append(SchemaError(path, f"{instance} >= exclusiveMaximum {schema['exclusiveMaximum']}"))

    def _check_array(self, instance: list, schema: Mapping[str, Any], path: str) -> None:
        if "minItems" in schema and len(instance) < int(schema["minItems"]):
            self.errors.append(SchemaError(path, f"array has {len(instance)} items, minItems is {schema['minItems']}"))
        if "maxItems" in schema and len(instance) > int(schema["maxItems"]):
            self.errors.append(SchemaError(path, f"array has {len(instance)} items, maxItems is {schema['maxItems']}"))
        if schema.get("uniqueItems"):
            seen: list[Any] = []
            for item in instance:
                if item in seen:
                    self.errors.append(SchemaError(path, f"array items are not unique: {item!r}"))
                    break
                seen.append(item)
        items = schema.get("items")
        if isinstance(items, Mapping):
            for i, item in enumerate(instance):
                self.validate(item, items, f"{path}/{i}")
        elif isinstance(items, list):
            for i, sub in enumerate(items):
                if i < len(instance) and isinstance(sub, Mapping):
                    self.validate(instance[i], sub, f"{path}/{i}")

    def _check_object(self, instance: dict, schema: Mapping[str, Any], path: str) -> None:
        required = schema.get("required") or []
        for key in required:
            if key not in instance:
                self.errors.append(SchemaError(path or "", f"missing required property {key!r}"))
        if "minProperties" in schema and len(instance) < int(schema["minProperties"]):
            self.errors.append(SchemaError(path, f"object has {len(instance)} properties, minProperties is {schema['minProperties']}"))
        if "maxProperties" in schema and len(instance) > int(schema["maxProperties"]):
            self.errors.append(SchemaError(path, f"object has {len(instance)} properties, maxProperties is {schema['maxProperties']}"))

        props = schema.get("properties") or {}
        for key, sub in props.items():
            if key in instance and isinstance(sub, Mapping):
                self.validate(instance[key], sub, f"{path}/{key}")

        additional = schema.get("additionalProperties", True)
        if additional is False:
            extra = [k for k in instance if k not in props]
            if extra:
                self.errors.append(SchemaError(path, f"additional properties not allowed: {sorted(extra)}"))
        elif isinstance(additional, Mapping):
            for key in instance:
                if key not in props:
                    self.validate(instance[key], additional, f"{path}/{key}")

    def _check_combinators(self, instance: Any, schema: Mapping[str, Any], path: str) -> None:
        for key in ("allOf",):
            for i, sub in enumerate(schema.get(key) or []):
                if isinstance(sub, Mapping):
                    self.validate(instance, sub, path)

        if "anyOf" in schema:
            results = [self._sub_validates(instance, sub) for sub in schema["anyOf"]]
            if results and not any(results):
                self.errors.append(SchemaError(path, "does not match any of the anyOf subschemas"))

        if "oneOf" in schema:
            results = [self._sub_validates(instance, sub) for sub in schema["oneOf"]]
            if results and sum(1 for r in results if r) != 1:
                self.errors.append(SchemaError(path, "must match exactly one oneOf subschema"))

        if "not" in schema and isinstance(schema["not"], Mapping):
            if self._sub_validates(instance, schema["not"]):
                self.errors.append(SchemaError(path, "must not match the 'not' subschema"))

    def _check_conditionals(self, instance: Any, schema: Mapping[str, Any], path: str) -> None:
        if "if" not in schema:
            return
        if_schema = schema["if"]
        if not isinstance(if_schema, Mapping):
            return
        matched = self._sub_validates(instance, if_schema)
        branch = schema.get("then") if matched else schema.get("else")
        if isinstance(branch, Mapping):
            self.validate(instance, branch, path)

    def _sub_validates(self, instance: Any, schema: Mapping[str, Any]) -> bool:
        """Run *schema* against *instance* in an isolated validator."""
        sub = _Validator(self.root)
        sub.validate(instance, schema, "")
        return not sub.errors


def validate_instance(
    instance: Any,
    schema: Mapping[str, Any],
    *,
    use_jsonschema: Optional[bool] = None,
) -> list[SchemaError]:
    """Validate *instance* against *schema*; return a list of errors (empty == valid)."""
    if use_jsonschema is None:
        use_jsonschema = HAS_JSONSCHEMA
    if use_jsonschema and HAS_JSONSCHEMA:
        try:
            validator_cls = _jsonschema.validators.validator_for(dict(schema))
            validator = validator_cls(dict(schema))
            return [
                SchemaError("/".join(str(p) for p in err.absolute_path), err.message)
                for err in validator.iter_errors(instance)
            ]
        except Exception:  # pragma: no cover - fall back on any jsonschema problem
            pass
    v = _Validator(schema)
    v.validate(instance, schema, "")
    return v.errors


def validate_instance_raise(
    instance: Any,
    schema: Mapping[str, Any],
    *,
    artifact: str = "",
    use_jsonschema: Optional[bool] = None,
) -> None:
    errors = validate_instance(instance, schema, use_jsonschema=use_jsonschema)
    if errors:
        raise SchemaValidationError(errors, artifact=artifact)


def validate_against_schema_name(
    instance: Any,
    schema_name: str,
    *,
    artifact: str = "",
    use_jsonschema: Optional[bool] = None,
) -> list[SchemaError]:
    """Load a shipped schema by name and validate *instance* against it."""
    schema = load_schema(schema_name)
    return validate_instance(instance, schema, use_jsonschema=use_jsonschema)


def errors_to_dicts(errors: Iterable[SchemaError]) -> list[dict[str, str]]:
    return [e.to_dict() for e in errors]
