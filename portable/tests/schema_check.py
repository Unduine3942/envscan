"""Minimal JSON Schema (draft 2020-12) validator for the subset used by schema/envscan.schema.json.

Supported keywords are listed in _SUPPORTED; any other keyword raises SchemaError, so a
schema change can never be silently ignored. Semantics follow the specification where
Python differs from JSON:
  * enum/const compare JSON values: false is not 0 and true is not 1;
  * pattern uses ECMA-262 anchors: "$" matches only at the very end, not before a final "\\n";
  * $ref (local "#/$defs/<name>" only) may point at another $ref; keywords next to a
    $ref apply as well; a missing definition or a reference cycle raises SchemaError.
Boolean schemas (true / false) are accepted wherever a schema is expected.
The jsonschema package is not assumed to be installed on the dev box.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from functools import cache
from typing import Any

_ANNOTATIONS = frozenset({"$schema", "$id", "$comment", "$defs", "title", "description", "default", "examples"})
_ASSERTIONS = frozenset({"$ref", "const", "enum", "type", "required", "properties",
                         "additionalProperties", "items", "pattern", "minimum"})
_SUPPORTED = _ANNOTATIONS | _ASSERTIONS
_REF_PREFIX = "#/$defs/"


class SchemaError(ValueError):
    """The schema uses something this validator does not support, or is malformed."""


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


_TYPES: Mapping[str, Callable[[Any], bool]] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": _is_number,
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _json_equal(left: Any, right: Any) -> bool:
    """Equality of JSON values: booleans never equal numbers; 1 equals 1.0."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if _is_number(left) and _is_number(right):
        return left == right
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_json_equal(left[key], right[key]) for key in left)
    if type(left) is not type(right):
        return False
    return left == right


def _ecma_pattern(pattern: str) -> str:
    """Translate ECMA-262 anchors: an unescaped "$" outside a character class becomes \\Z."""
    out: list[str] = []
    index, in_class = 0, False
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            out.append(pattern[index:index + 2])
            index += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
        elif char == "$":
            char = r"\Z"
        out.append(char)
        index += 1
    return "".join(out)


@cache
def _regex(pattern: str) -> re.Pattern[str]:
    try:
        # re.ASCII: \d and \w mean [0-9] and [A-Za-z0-9_], as in ECMA-262.
        return re.compile(_ecma_pattern(pattern), re.ASCII)
    except re.error as exc:
        raise SchemaError(f"invalid pattern {pattern!r}: {exc}") from exc


def _lookup(ref: Any, root: Mapping[str, Any]) -> Any:
    if not isinstance(ref, str) or not ref.startswith(_REF_PREFIX) or "/" in ref[len(_REF_PREFIX):]:
        raise SchemaError(f"unsupported $ref {ref!r}: only '#/$defs/<name>' is supported")
    name = ref[len(_REF_PREFIX):].replace("~1", "/").replace("~0", "~")
    definitions = root.get("$defs", {})
    if not isinstance(definitions, Mapping) or name not in definitions:
        raise SchemaError(f"$ref {ref!r}: no definition {name!r} in $defs")
    return definitions[name]


def _check_schema(schema: Any, root: Mapping[str, Any], where: str) -> None:
    """Walk the whole schema once: unsupported keywords and dangling refs fail even if unused."""
    if isinstance(schema, bool):
        return
    if not isinstance(schema, Mapping):
        raise SchemaError(f"{where}: a schema must be an object or a boolean, got {type(schema).__name__}")
    unsupported = sorted(set(schema) - _SUPPORTED)
    if unsupported:
        raise SchemaError(f"{where}: unsupported keyword(s) {unsupported}")
    if "$ref" in schema:
        _lookup(schema["$ref"], root)
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        unknown = [name for name in names if name not in _TYPES]
        if unknown:
            raise SchemaError(f"{where}: unknown type(s) {unknown}")
    if "pattern" in schema:
        _regex(schema["pattern"])
    if "enum" in schema and not isinstance(schema["enum"], list):
        raise SchemaError(f"{where}: enum must be an array")
    required = schema.get("required", [])
    if not isinstance(required, list) or not all(isinstance(key, str) for key in required):
        raise SchemaError(f"{where}: required must be an array of strings")
    if "minimum" in schema and not _is_number(schema["minimum"]):
        raise SchemaError(f"{where}: minimum must be a number")
    if isinstance(schema.get("items"), list):
        raise SchemaError(f"{where}: array-form items is not supported")
    for keyword in ("properties", "$defs"):
        children = schema.get(keyword, {})
        if not isinstance(children, Mapping):
            raise SchemaError(f"{where}: {keyword} must be an object")
        for key, child in children.items():
            _check_schema(child, root, f"{where}/{keyword}/{key}")
    for keyword in ("additionalProperties", "items"):
        if keyword in schema:
            _check_schema(schema[keyword], root, f"{where}/{keyword}")


def _check_object(instance: dict, schema: Mapping[str, Any], root: Mapping[str, Any], path: str) -> list[str]:
    errors = [f"{path}: missing required '{key}'" for key in schema.get("required", []) if key not in instance]
    properties = schema.get("properties", {})
    extra = schema.get("additionalProperties", True)
    for key, value in instance.items():
        child = f"{path}.{key}"
        if key in properties:
            errors.extend(_validate(value, properties[key], root, child, ()))
        elif extra is False:
            errors.append(f"{path}: unexpected property '{key}'")
        elif extra is not True:
            errors.extend(_validate(value, extra, root, child, ()))
    return errors


def _validate(instance: Any, schema: Any, root: Mapping[str, Any], path: str, refs: tuple[str, ...]) -> list[str]:
    if schema is True:
        return []
    if schema is False:
        return [f"{path}: no value is allowed here"]
    errors: list[str] = []
    if "$ref" in schema:
        ref = schema["$ref"]
        if ref in refs:
            raise SchemaError(f"{path}: $ref cycle {' -> '.join((*refs, ref))}")
        errors.extend(_validate(instance, _lookup(ref, root), root, path, (*refs, ref)))
    if "const" in schema and not _json_equal(instance, schema["const"]):
        return [*errors, f"{path}: expected {schema['const']!r}, got {instance!r}"]
    if "enum" in schema and not any(_json_equal(instance, option) for option in schema["enum"]):
        return [*errors, f"{path}: {instance!r} not in {schema['enum']!r}"]
    expected = schema.get("type")
    if expected is not None:
        names = expected if isinstance(expected, list) else [expected]
        if not any(_TYPES[name](instance) for name in names):
            return [*errors, f"{path}: expected type {expected}, got {type(instance).__name__}"]
    if isinstance(instance, dict):
        errors.extend(_check_object(instance, schema, root, path))
    if isinstance(instance, list) and "items" in schema:
        for index, item in enumerate(instance):
            errors.extend(_validate(item, schema["items"], root, f"{path}[{index}]", ()))
    if isinstance(instance, str) and "pattern" in schema and not _regex(schema["pattern"]).search(instance):
        errors.append(f"{path}: {instance!r} does not match {schema['pattern']}")
    if _is_number(instance) and "minimum" in schema and instance < schema["minimum"]:
        errors.append(f"{path}: {instance} < minimum {schema['minimum']}")
    return errors


def validate(instance: Any, schema: Mapping[str, Any], root: Mapping[str, Any] | None = None,
             path: str = "$") -> list[str]:
    """Return a list of validation errors (empty when valid).

    Raises SchemaError when the schema itself uses an unsupported keyword or form.
    """
    if root is None:
        root = schema
        _check_schema(schema, root, "#")
    return _validate(instance, schema, root, path, ())
