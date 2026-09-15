"""Tests for runtime/schema.py — stdlib JSON Schema subset validator."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.schema import (
    SchemaValidationError,
    load_schema,
    resolve_schema_dir,
    schema_path,
    validate_against_schema_name,
    validate_instance,
    validate_instance_raise,
)


def test_schema_dir_resolves_to_shipped_schemas() -> None:
    d = resolve_schema_dir()
    assert d.is_dir()
    assert (d / "finding.schema.json").exists()


def test_schema_path_accepts_short_and_long_names() -> None:
    assert schema_path("finding").name == "finding.schema.json"
    assert schema_path("finding.schema.json").name == "finding.schema.json"


def test_type_checking() -> None:
    assert validate_instance(1, {"type": "integer"}) == []
    assert validate_instance("x", {"type": "integer"})
    assert validate_instance(True, {"type": "integer"}), "bool is not an integer"
    assert validate_instance(1.5, {"type": "number"}) == []
    assert validate_instance(True, {"type": "number"}), "bool is not a number"
    assert validate_instance(1, {"type": ["integer", "string"]}) == []
    assert validate_instance(None, {"type": "null"}) == []
    assert validate_instance([], {"type": "object"})


def test_required_and_properties() -> None:
    schema = {
        "type": "object",
        "required": ["a"],
        "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
    }
    assert validate_instance({"a": "x", "b": 1}, schema) == []
    errs = validate_instance({"b": "not-int"}, schema)
    assert any("missing required property 'a'" in e.message for e in errs)


def test_additional_properties_false() -> None:
    schema = {"type": "object", "properties": {"a": {"type": "string"}},
              "additionalProperties": False}
    assert validate_instance({"a": "x"}, schema) == []
    errs = validate_instance({"a": "x", "z": 1}, schema)
    assert any("additional properties" in e.message for e in errs)


def test_additional_properties_schema() -> None:
    schema = {"type": "object", "additionalProperties": {"type": "string"}}
    assert validate_instance({"a": "x"}, schema) == []
    assert validate_instance({"a": 1}, schema)


def test_enum_and_const() -> None:
    assert validate_instance("a", {"enum": ["a", "b"]}) == []
    assert validate_instance("c", {"enum": ["a", "b"]})
    assert validate_instance(1, {"const": 1}) == []
    assert validate_instance(2, {"const": 1})
    # bool/int trap: True must not satisfy enum [1]
    assert validate_instance(True, {"enum": [1]})


def test_string_constraints() -> None:
    assert validate_instance("abc", {"minLength": 2, "maxLength": 5}) == []
    assert validate_instance("a", {"minLength": 2})
    assert validate_instance("abcdef", {"maxLength": 5})
    assert validate_instance("F-001", {"pattern": "^F-[0-9]{3,}$"}) == []
    assert validate_instance("X-1", {"pattern": "^F-[0-9]{3,}$"})


def test_number_constraints() -> None:
    assert validate_instance(5, {"minimum": 1, "maximum": 10}) == []
    assert validate_instance(0, {"minimum": 1})
    assert validate_instance(11, {"maximum": 10})
    assert validate_instance(1, {"exclusiveMinimum": 1})
    assert validate_instance(10, {"exclusiveMaximum": 10})


def test_array_constraints() -> None:
    assert validate_instance([1, 2], {"type": "array", "minItems": 1, "items": {"type": "integer"}}) == []
    assert validate_instance([], {"minItems": 1})
    assert validate_instance([1, 2, 3], {"maxItems": 2})
    assert validate_instance([1, 2, 1], {"uniqueItems": True})
    assert validate_instance(["x"], {"items": {"type": "integer"}})


def test_combinators() -> None:
    assert validate_instance(3, {"allOf": [{"minimum": 1}, {"maximum": 5}]}) == []
    assert validate_instance(9, {"allOf": [{"minimum": 1}, {"maximum": 5}]})
    assert validate_instance("x", {"anyOf": [{"type": "string"}, {"type": "integer"}]}) == []
    assert validate_instance([], {"anyOf": [{"type": "string"}, {"type": "integer"}]})
    assert validate_instance(3, {"oneOf": [{"minimum": 1}, {"maximum": 5}]}), "matches both"
    assert validate_instance(3, {"oneOf": [{"minimum": 1}, {"maximum": 2}]}) == []
    assert validate_instance("x", {"not": {"type": "string"}})


def test_if_then_else() -> None:
    schema = {
        "type": "object",
        "properties": {"kind": {"type": "string"}},
        "if": {"properties": {"kind": {"const": "a"}}, "required": ["kind"]},
        "then": {"required": ["only_for_a"]},
        "else": {"required": ["for_others"]},
    }
    assert validate_instance({"kind": "a", "only_for_a": 1}, schema) == []
    assert validate_instance({"kind": "a"}, schema)
    assert validate_instance({"kind": "b", "for_others": 1}, schema) == []
    assert validate_instance({"kind": "b"}, schema)


def test_ref_to_defs() -> None:
    schema = {
        "type": "object",
        "properties": {"unit": {"$ref": "#/$defs/Unit"}},
        "$defs": {
            "Unit": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}},
        },
    }
    assert validate_instance({"unit": {"id": "x"}}, schema) == []
    errs = validate_instance({"unit": {}}, schema)
    assert any("id" in e.message for e in errs)


def test_self_referential_ref_does_not_loop() -> None:
    schema = {"$defs": {"Node": {"type": "object",
                                 "properties": {"next": {"$ref": "#/$defs/Node"}}}},
              "$ref": "#/$defs/Node"}
    assert validate_instance({"next": {"next": {}}}, schema) == []


def test_error_shape_and_raise() -> None:
    errs = validate_instance({"a": 1}, {"type": "object", "properties": {"b": {"type": "string"}}},
                             use_jsonschema=False)
    # b is absent — optional — so no errors; now force one
    errs = validate_instance({"b": 1}, {"properties": {"b": {"type": "string"}}},
                             use_jsonschema=False)
    assert errs
    e = errs[0]
    assert e.path == "/b"
    assert isinstance(e.to_dict(), dict)
    with pytest.raises(SchemaValidationError):
        validate_instance_raise({"b": 1}, {"properties": {"b": {"type": "string"}}},
                                artifact="x.json")


def test_finding_schema_rejects_and_accepts() -> None:
    from runtime.fingerprint import compute_fingerprint

    good = {
        "id": "F-001",
        "verdict": "confirmed",
        "class": "idor",
        "title": "IDOR",
        "summary": "user can read other tenants data",
        "source_ref": {"commit": "abc", "tree_hash": "t"},
        "boundary": {"type": "tenant", "security_invariant": "no cross-tenant", "crossed": True},
        "trace": [{"kind": "sink", "file": "x.py", "line": 1, "symbol": "f"}],
        "severity": {"overall": "high"},
        "verification": {"technical_verifier": "v1"},
    }
    good["fingerprint"] = compute_fingerprint(good)
    assert validate_against_schema_name(good, "finding") == []

    bad = dict(good)
    bad["fingerprint"] = "not-a-fingerprint"
    assert validate_against_schema_name(bad, "finding")


def test_rejected_requires_disposition_via_if_then() -> None:
    from runtime.fingerprint import compute_fingerprint

    base = {
        "id": "F-002",
        "verdict": "rejected",
        "class": "rce",
        "title": "Admin can exec",
        "summary": "admin already has exec capability by design",
        "source_ref": {"commit": "abc", "tree_hash": "t"},
        "trace": [{"kind": "sink", "file": "x.py", "line": 1, "symbol": "exec"}],
    }
    base["fingerprint"] = compute_fingerprint(base)
    assert validate_against_schema_name(base, "finding"), "rejected without reason must fail"

    base["disposition_reason"] = "by_design"
    base["fingerprint"] = compute_fingerprint(base)
    assert validate_against_schema_name(base, "finding") == []


def test_loading_unknown_schema_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_schema("does-not-exist")


def test_all_shipped_schemas_load_and_are_dicts() -> None:
    d = resolve_schema_dir()
    for path in sorted(d.glob("*.schema.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(payload, dict)
        assert "$schema" in payload
