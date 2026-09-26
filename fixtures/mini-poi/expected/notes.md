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
      "trust_source": "MiniPoiPlugin::handle() return value (fixtures/mini-poi/plugin.php:13)",
      "trust_consumer": "unserialize() in mini_poi_serve_page() (fixtures/mini-poi/index.php:43)",
      "status": "upgraded",
      "file_line": "fixtures/mini-poi/index.php:38-43",
      "rationale": "hostile plugin handle() returns an object; serialize() persists it; unserialize() on the next request instantiates it and runs __wakeup. No allowed_classes filter anywhere on the read path."
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