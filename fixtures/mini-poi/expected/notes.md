# Audit Notes -- mini-poi fixture

> Reference output of a correct audit on fixtures/mini-poi/.
> This file is what `runtime/regression.py` checks. Real
> audits on real targets should look structurally similar
> but with target-specific content.

---

## Objective

Mini-POI: a minimal PHP deserialization object-injection
fixture. The audit is to find the POI chain similar to
DokuWiki Issue #4752 (CWE-502) and write it up.

## Attack Surface

- `fixtures/mini-poi/index.php` -- request handler. Calls
  `mini_poi_parse()` then `mini_poi_serve_page()`.
- `fixtures/mini-poi/plugin.php` -- `MiniPoiPlugin::handle()`
  is the trust-source: it returns whatever the attacker chose.

## Coverage

Plugin handle() return value is the attacker-controlled
data path. The application has exactly one trust-source /
trust-consumer pair to enumerate:

- trust-source: `MiniPoiPlugin::handle()` return value
- trust-consumer: `unserialize()` in
  `mini_poi_serve_page()`

There is one protocol entry into `handle()`: the
`!plugin!` line in `index.php` parser. No other ingress.

## Class Coverage

The four baseline lenses are all recorded in the machine-readable table below.
The two N/A conclusions are supported by distinct searches and scoped fixture
evidence.

## Guard Evaluation Ledger

The `unserialize()` consumer has no class restriction. Its call expression and
the hostile serialized-object input are evaluated in the machine-readable row
below.

## Verified Facts

1. `MiniPoiPlugin::handle()` has no return-type contract.
   `fixtures/mini-poi/plugin.php:13` (the return statement
   `[ 'instruction' => $arg ]` is the literal the fixture
   ships with; a hostile variant returns an object).
2. `index.php:38` calls `serialize()` on the parser calls
   array -- which includes the plugin's return value --
   without filtering by type.
3. `index.php:43` calls `unserialize()` on the cache file
   without `[allowed_classes => false]`.
4. The two are linked by file path: `mini_poi_store_cache`
   writes, `mini_poi_serve_page` reads.

## Synthesize Pairing Table

```json
{
  "rows": [
    {
      "category": "callback_to_sink",
      "trust_source": "MiniPoiPlugin::handle() return value (fixtures/mini-poi/plugin.php:13)",
      "trust_consumer": "unserialize() in mini_poi_serve_page() (fixtures/mini-poi/index.php:43)",
      "attacker_reach": "The !plugin! parser entry reaches MiniPoiPlugin::handle() and stores its return value in the cache.",
      "status": "upgraded",
      "file_line": "fixtures/mini-poi/index.php:38-43",
      "rationale": "hostile plugin handle() returns an object; serialize() persists it; unserialize() on the next request instantiates it and runs __wakeup. No allowed_classes filter anywhere on the read path."
    }
  ],
  "class_coverage": [
    {
      "category": "authz_sensitive_write",
      "status": "N/A",
      "strategy": "Search for authentication, authorization, role, owner, and tenant fields or decisions in the complete fixture.",
      "evidence": ["No authn/authz decision appears in the fixture files (fixtures/mini-poi/index.php:1-43; fixtures/mini-poi/plugin.php:1-19)."],
      "absence_searches": [
        {"query": "rg -n 'role|owner|tenant|authtype|permission' fixtures/mini-poi", "result": "0 matches"},
        {"query": "rg -n 'auth|authorize|can\\(|ACL|permission' fixtures/mini-poi", "result": "0 matches"}
      ],
      "reason": "This fixture has only a parser, plugin callback, cache writer, and cache reader; it has no authentication or authorization model."
    },
    {
      "category": "identity_to_decision",
      "status": "N/A",
      "strategy": "Search for asserted identity sources and consumers such as headers, peer identity, DNS, tokens, and ACL decisions.",
      "evidence": ["No identity or access-control consumer exists in the fixture (fixtures/mini-poi/index.php:1-43)."],
      "absence_searches": [
        {"query": "rg -n 'proxy|forwarded|remote_addr|DNS|token|principal' fixtures/mini-poi", "result": "0 matches"},
        {"query": "rg -n 'ACL|allow|deny|authorize|access check' fixtures/mini-poi", "result": "0 matches"}
      ],
      "reason": "The fixture has no network identity or access-control decision."
    },
    {
      "category": "callback_to_sink",
      "status": "HUNTED",
      "strategy": "Trace the plugin callback return into persistent storage and every deserialization or other dangerous consumer.",
      "evidence": ["fixtures/mini-poi/plugin.php:13", "fixtures/mini-poi/index.php:38-43"]
    },
    {
      "category": "state_cross_endpoint",
      "status": "HUNTED",
      "strategy": "Trace state written by one request path to reads on later requests and identify the trust decision at the reader.",
      "evidence": ["fixtures/mini-poi/index.php:38-43"]
    }
  ],
  "guard_checks": [
    {
      "protected_consumer": "Object deserialization in mini_poi_serve_page()",
      "guard_location": "fixtures/mini-poi/index.php:43",
      "expression": "unserialize($cache)",
      "attacker_input_shape": "Attacker-controlled serialized object returned by the plugin and persisted in the cache file.",
      "evaluated_result": "The value reaches unserialize() without an allowed_classes restriction; the object is instantiated and __wakeup runs.",
      "verdict": "ineffective"
    }
  ],
  "coverage_paragraph_present": true
}
```

## Hypotheses

(none remaining after Verify promoted the chain to Verified
Fact.)

## Blocked Leads

(none.)

## Remaining Questions

(none.)
