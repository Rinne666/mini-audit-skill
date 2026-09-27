# Audit Notes -- mini-poi fixture

> Reference output for the format and evidence-ledger checks in
> `runtime/regression.py`. It does not demonstrate LLM-in-the-loop recall.

---

## Objective

Mini-POI: a minimal PHP deserialization object-injection fixture. The target
question is whether a plugin return value can cross the cache boundary and
reach a later deserialization consumer.

## Attack Surface

- `fixtures/mini-poi/index.php:35-40` -- `!plugin!` page text reaches
  `MiniPoiPlugin::handle()` and its return is stored in the parser calls.
- `fixtures/mini-poi/index.php:23-27` -- the parsed call data is serialized
  into the cache file.
- `fixtures/mini-poi/index.php:46-50` -- a later page request reads and
  deserializes the cache.

## Coverage

The `!plugin!` parser entry is the only ingress in this fixture. The value
flows through a cache write in `mini_poi_store_cache()` and a later read in
`mini_poi_serve_page()`. Captured source reads: `E000001` and `E000002`.

## Class Coverage

All four baseline categories have an explicit status. The two N/A conclusions
are limited to this small fixture and cite captured zero-match searches.

## Work Queue

The four baseline passes are closed. Callback-to-sink and cross-endpoint-state
received the deeper traces because they reach the deserialization consumer.
The machine-readable `work_queue` below is the source of truth; every task is
completed or deferred with an outcome.

## Guard Evaluation Ledger

The captured call at `fixtures/mini-poi/index.php:49` has no class restriction.
`E000001` contains the source expression and read path.

## Verified Facts

1. `MiniPoiPlugin::handle()` declares a `mixed` return type at
   `fixtures/mini-poi/plugin.php:13`; the shipped fixture returns an array at
   line 19. A hostile plugin implementation can return an object.
2. The parser stores the callback return at
   `fixtures/mini-poi/index.php:35-40`, then serializes the parser calls at
   line 27.
3. A later request calls `unserialize(file_get_contents($cache_path))` at
   `fixtures/mini-poi/index.php:49` without an `allowed_classes` restriction.
4. The writer and reader share the cache path; captured in `E000001`.

## Hypotheses

(none remaining after Verify promoted the chain to a Verified Fact.)

## Blocked Leads

(none.)

## Remaining Questions

(none.)

## Synthesize Pairing Table

```json
{
  "rows": [
    {
      "category": "callback_to_sink",
      "trust_source": "MiniPoiPlugin::handle() return value (fixtures/mini-poi/plugin.php:13-19)",
      "trust_consumer": "unserialize() in mini_poi_serve_page() (fixtures/mini-poi/index.php:49)",
      "attacker_reach": "The !plugin! parser entry passes the plugin return into the cache written at line 27 and read by a later request.",
      "status": "upgraded",
      "file_line": "fixtures/mini-poi/index.php:27-49",
      "rationale": "A hostile plugin can return an object; serialize() persists it and the later unrestricted unserialize() instantiates it.",
      "evidence_ids": ["E000001", "E000002"]
    }
  ],
  "class_coverage": [
    {
      "category": "authz_sensitive_write",
      "status": "N/A",
      "strategy": "Search the fixture source for sensitive writes and authentication/authorization decisions.",
      "evidence": ["The fixture has no authn/authz model (E000003, E000004)."],
      "evidence_ids": ["E000003", "E000004"],
      "absence_searches": [{"evidence_id": "E000003"}, {"evidence_id": "E000004"}],
      "reason": "The two captured searches found no sensitive fields or access-decision code in the fixture source."
    },
    {
      "category": "identity_to_decision",
      "status": "N/A",
      "strategy": "Search the fixture source for asserted identities and ACL consumers.",
      "evidence": ["The fixture has no identity or ACL decision path (E000005, E000006)."],
      "evidence_ids": ["E000005", "E000006"],
      "absence_searches": [{"evidence_id": "E000005"}, {"evidence_id": "E000006"}],
      "reason": "The two captured searches found no proxy, DNS, token, or access-control decision code in the fixture source."
    },
    {
      "category": "callback_to_sink",
      "status": "HUNTED",
      "strategy": "Trace the plugin callback return through persistence to every deserialization consumer.",
      "evidence": ["fixtures/mini-poi/index.php:27-49", "fixtures/mini-poi/plugin.php:13-19"],
      "evidence_ids": ["E000001", "E000002"]
    },
    {
      "category": "state_cross_endpoint",
      "status": "HUNTED",
      "strategy": "Trace the cache writer and the later request path that consumes the cached state.",
      "evidence": ["fixtures/mini-poi/index.php:23-27", "fixtures/mini-poi/index.php:46-50"],
      "evidence_ids": ["E000001"]
    }
  ],
  "work_queue": [
    {
      "id": "W1",
      "category": "authz_sensitive_write",
      "task": "Search for sensitive writes and authorization consumers.",
      "priority": "medium",
      "reason": "Mandatory baseline coverage.",
      "budget_unit": "One bounded search pass with two targeted patterns.",
      "stop_condition": "Stop after the two searches return no matches or a source path is found.",
      "status": "completed",
      "outcome": "No authorization or sensitive-write path was present in this fixture.",
      "evidence_ids": ["E000003", "E000004"]
    },
    {
      "id": "W2",
      "category": "identity_to_decision",
      "task": "Search asserted identities and ACL consumers.",
      "priority": "medium",
      "reason": "Mandatory baseline coverage.",
      "budget_unit": "One bounded search pass with two targeted patterns.",
      "stop_condition": "Stop after the two searches return no matches or a source path is found.",
      "status": "completed",
      "outcome": "No identity assertion or ACL decision path was present in this fixture.",
      "evidence_ids": ["E000005", "E000006"]
    },
    {
      "id": "W3",
      "category": "callback_to_sink",
      "task": "Trace the plugin callback return through cache persistence to deserialization.",
      "priority": "high",
      "reason": "The callback return may cross into an unsafe object consumer.",
      "budget_unit": "One bounded source trace across the callback, writer, and reader.",
      "stop_condition": "Stop when the attacker-control precondition and sink behavior are explicit.",
      "status": "completed",
      "outcome": "The cache-to-unserialize shape is present; attacker control and gadget availability remain explicit deployment assumptions.",
      "evidence_ids": ["E000001", "E000002"]
    },
    {
      "id": "W4",
      "category": "state_cross_endpoint",
      "task": "Correlate the cache writer and later request reader.",
      "priority": "high",
      "reason": "The value crosses a request boundary before it is consumed.",
      "budget_unit": "One bounded source trace over the cache path and both request paths.",
      "stop_condition": "Stop when the producer and consumer share a cited state path.",
      "status": "completed",
      "outcome": "The same cache path connects writer and reader across requests.",
      "evidence_ids": ["E000001"]
    },
    {
      "id": "W5",
      "category": "final_review",
      "task": "Challenge both N/A decisions, the attacker-control assumption, and the deserialization guard verdict.",
      "priority": "high",
      "reason": "The final pass targets likely false negatives and overclaimed impact.",
      "budget_unit": "One bounded adversarial review of the four baseline results and the high-impact chain.",
      "stop_condition": "Stop after each negative or high-impact conclusion has been challenged against its cited artifacts.",
      "status": "completed",
      "outcome": "The N/A searches are distinct; object injection remains conditional on attacker-controlled plugin output, and RCE is not established without a gadget.",
      "evidence_ids": ["E000001", "E000002", "E000003", "E000004", "E000005", "E000006"]
    }
  ],
  "guard_checks": [
    {
      "protected_consumer": "Object deserialization in mini_poi_serve_page()",
      "guard_location": "fixtures/mini-poi/index.php:49",
      "expression": "unserialize(file_get_contents($cache_path))",
      "attacker_input_shape": "A serialized object returned by a plugin and persisted in the cache file.",
      "evaluated_result": "The call has no allowed_classes restriction; PHP instantiates the object and may invoke __wakeup.",
      "verdict": "ineffective",
      "evidence_ids": ["E000001"]
    }
  ],
  "coverage_paragraph_present": true
}
```
