# Candidate — unsafe deserialization across the plugin cache boundary

> Reference finding for the mini-poi fixture. It demonstrates a conditional
> object-injection path, not a complete remote-code-execution exploit.

## Candidate Review

- Candidate ID: `C1`
- Independent verifier ID: `candidate-verifier-1`
- Verdict: `needs_validation`
- Evidence IDs: `E000001`, `E000002`
- The object-instantiation sink behavior is source-confirmed under the stated
  input shape. Attacker control of a plugin implementation and a usable loaded
  gadget are not established by this fixture. This document is a conditional
  review draft; it must not be counted as a confirmed finding.

## Summary

`mini_poi_serve_page()` deserializes cached parser calls without an
`allowed_classes` restriction. If an attacker can influence a plugin's
`handle()` return value into an object, that object can cross the cache
boundary and be instantiated on a later request. The checked-in plugin
returns an array, so the source alone does not show that an ordinary page
editor can control the return type. Code execution additionally depends on a
usable gadget class being loaded.

## Severity

Exploitability and impact are deployment-dependent. Treat remote object
injection as unconfirmed until attacker control of the plugin return is
established; claim code execution only after identifying a reachable gadget
or equivalent effect.

## Location

- `fixtures/mini-poi/index.php:27` — serializes parser calls into the cache.
- `fixtures/mini-poi/index.php:49` — deserializes the cache without a class
  restriction.
- `fixtures/mini-poi/index.php:38-40` — stores the plugin return in the
  serialized value.
- `fixtures/mini-poi/plugin.php:13-19` — the current handler returns `mixed`
  by declaration but the shipped implementation returns an array.

## Preconditions

- The attacker can cause a plugin handler to return an attacker-selected
  object, for example by controlling a plugin implementation or an object
  returned from attacker-controlled plugin input. Page-edit permission alone
  does not establish this precondition in the checked-in fixture.
- For code execution, the later request must load a class with a usable
  deserialization gadget whose effects the attacker can influence.

## Attack path

1. An attacker-controlled or otherwise untrusted plugin path returns an
   object from `MiniPoiPlugin::handle()`.
2. A page containing `!plugin! ...` reaches `handle()` at
   `index.php:35-40`; the return value is stored in the parser calls.
3. `index.php:27` serializes those calls to the cache file.
4. A later request reads that file and invokes unrestricted `unserialize()`
   at `index.php:49`, instantiating the object. A loaded gadget may then
   produce a security impact.

## Evidence and limitations

- `E000001` captures the cache writer and deserializer, including the
  unrestricted call at `index.php:49`.
- `E000002` captures the plugin handler's `mixed` return declaration and
  current array result.
- The fixture does not contain an attacker-controlled plugin implementation
  or a gadget class. Those are deployment preconditions, not facts proven by
  this sample.

## Remediation

- Avoid native object deserialization for cache data. Prefer a data-only
  format; if native serialization must remain, use an explicit class allowlist
  and validate the decoded structure before use.
- Constrain and validate the plugin return type at the call site. A declared
  return type alone is insufficient if it permits arbitrary object values.
