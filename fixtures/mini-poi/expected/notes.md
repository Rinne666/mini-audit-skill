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

## Coverage Units and Reviews

The four baseline dimensions produce four stable coverage units. Each unit names
its source refs, entry points, paths, owner, wave, budget unit, outcome, and
evidence. The post-wave critic and final-clean reviewer are separate from all
unit owners and from each other.

## Candidate Review

Candidate `C1` remains `needs_validation`: object instantiation at the sink is
confirmed under the stated input shape, but this fixture does not prove an
attacker can control a plugin implementation or that an executable gadget is
loaded. The run is therefore marked incomplete, and the finding below is a
conditional review draft rather than a confirmed report.

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
      "evidence_ids": [
        "E000001",
        "E000002"
      ]
    }
  ],
  "class_coverage": [
    {
      "category": "authz_sensitive_write",
      "status": "N/A",
      "strategy": "Search the fixture source for sensitive writes and authentication/authorization decisions.",
      "evidence": [
        "The fixture has no authn/authz model (E000003, E000004)."
      ],
      "evidence_ids": [
        "E000003",
        "E000004"
      ],
      "absence_searches": [
        {
          "evidence_id": "E000003"
        },
        {
          "evidence_id": "E000004"
        }
      ],
      "reason": "The two captured searches found no sensitive fields or access-decision code in the fixture source."
    },
    {
      "category": "identity_to_decision",
      "status": "N/A",
      "strategy": "Search the fixture source for asserted identities and ACL consumers.",
      "evidence": [
        "The fixture has no identity or ACL decision path (E000005, E000006)."
      ],
      "evidence_ids": [
        "E000005",
        "E000006"
      ],
      "absence_searches": [
        {
          "evidence_id": "E000005"
        },
        {
          "evidence_id": "E000006"
        }
      ],
      "reason": "The two captured searches found no proxy, DNS, token, or access-control decision code in the fixture source."
    },
    {
      "category": "callback_to_sink",
      "status": "HUNTED",
      "strategy": "Trace the plugin callback return through persistence to every deserialization consumer.",
      "evidence": [
        "fixtures/mini-poi/index.php:27-49",
        "fixtures/mini-poi/plugin.php:13-19"
      ],
      "evidence_ids": [
        "E000001",
        "E000002"
      ]
    },
    {
      "category": "state_cross_endpoint",
      "status": "HUNTED",
      "strategy": "Trace the cache writer and the later request path that consumes the cached state.",
      "evidence": [
        "fixtures/mini-poi/index.php:23-27",
        "fixtures/mini-poi/index.php:46-50"
      ],
      "evidence_ids": [
        "E000001"
      ]
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
      "evidence_ids": [
        "E000001"
      ]
    }
  ],
  "coverage_paragraph_present": true,
  "coverage_units": [
    {
      "coverage_id": "CU-a0c0d3a49b4cb1d37c9951b6",
      "dimensions": {
        "surface": "fixture source inventory",
        "boundary": "untrusted page input -> authorization state",
        "subsystem": "authentication and authorization decisions",
        "attack_class": "authz_sensitive_write",
        "lifecycle": null
      },
      "baseline_category": "authz_sensitive_write",
      "source_refs": [
        "fixtures/mini-poi/index.php",
        "fixtures/mini-poi/plugin.php"
      ],
      "entry_points": [
        "no authorization ingress identified in this fixture inventory"
      ],
      "paths_in_scope": [
        "fixtures/mini-poi/index.php",
        "fixtures/mini-poi/plugin.php"
      ],
      "task": "Search low-privilege writes and authentication/authorization consumers.",
      "priority": "medium",
      "budget_unit": "one bounded two-query absence pass",
      "stop_condition": "Stop after two distinct targeted searches or when a source path is found.",
      "wave": 1,
      "owner_id": "hunter-authz",
      "status": "not_applicable",
      "outcome": "Two distinct searches found no authn/authz state in the fixture.",
      "absence_searches": [
        {
          "evidence_id": "E000003"
        },
        {
          "evidence_id": "E000004"
        }
      ],
      "evidence_ids": [
        "E000003",
        "E000004"
      ],
      "candidate_ids": []
    },
    {
      "coverage_id": "CU-c028b875c47b01a4686e4a61",
      "dimensions": {
        "surface": "fixture source inventory",
        "boundary": "asserted identity -> access decision",
        "subsystem": "identity and ACL consumers",
        "attack_class": "identity_to_decision",
        "lifecycle": null
      },
      "baseline_category": "identity_to_decision",
      "source_refs": [
        "fixtures/mini-poi/index.php",
        "fixtures/mini-poi/plugin.php"
      ],
      "entry_points": [
        "no asserted-identity ingress identified in this fixture inventory"
      ],
      "paths_in_scope": [
        "fixtures/mini-poi/index.php",
        "fixtures/mini-poi/plugin.php"
      ],
      "task": "Search asserted identities and ACL consumers.",
      "priority": "medium",
      "budget_unit": "one bounded two-query absence pass",
      "stop_condition": "Stop after two distinct targeted searches or when a source path is found.",
      "wave": 1,
      "owner_id": "hunter-identity",
      "status": "not_applicable",
      "outcome": "Two distinct searches found no asserted identity or ACL decision path.",
      "absence_searches": [
        {
          "evidence_id": "E000005"
        },
        {
          "evidence_id": "E000006"
        }
      ],
      "evidence_ids": [
        "E000005",
        "E000006"
      ],
      "candidate_ids": []
    },
    {
      "coverage_id": "CU-7919364f1cf0b876efad0a2e",
      "dimensions": {
        "surface": "page body !plugin! directive",
        "boundary": "plugin callback return -> cache -> unrestricted unserialize",
        "subsystem": "plugin parsing and page cache",
        "attack_class": "callback_to_sink",
        "lifecycle": "request-to-request"
      },
      "baseline_category": "callback_to_sink",
      "source_refs": [
        "fixtures/mini-poi/index.php:parse_page",
        "fixtures/mini-poi/plugin.php:MiniPoiPlugin::handle"
      ],
      "entry_points": [
        "page body !plugin! directive"
      ],
      "paths_in_scope": [
        "fixtures/mini-poi/index.php",
        "fixtures/mini-poi/plugin.php"
      ],
      "task": "Trace plugin callback output to persisted cache and every object consumer.",
      "priority": "high",
      "budget_unit": "one bounded source trace over callback, writer, and reader",
      "stop_condition": "Stop when attacker control, persistence, consumer behavior, and unresolved preconditions are explicit.",
      "wave": 1,
      "owner_id": "hunter-callback",
      "status": "candidate",
      "outcome": "Unsafe object-instantiation behavior is confirmed conditional on attacker-influenced plugin output; remote control and RCE are not established.",
      "evidence_ids": [
        "E000001",
        "E000002"
      ],
      "candidate_ids": [
        "C1"
      ]
    },
    {
      "coverage_id": "CU-9b8dd362eba2f2c4a06c4ca3",
      "dimensions": {
        "surface": "later page request cache read",
        "boundary": "cache writer request -> later request deserializer",
        "subsystem": "page cache persistence",
        "attack_class": "state_cross_endpoint",
        "lifecycle": "request-to-request"
      },
      "baseline_category": "state_cross_endpoint",
      "source_refs": [
        "fixtures/mini-poi/index.php:mini_poi_store_cache",
        "fixtures/mini-poi/index.php:mini_poi_serve_page"
      ],
      "entry_points": [
        "later page request reads cache written by parser request"
      ],
      "paths_in_scope": [
        "fixtures/mini-poi/index.php"
      ],
      "task": "Correlate cache writer and later request reader, including shared path and authorization context.",
      "priority": "high",
      "budget_unit": "one bounded writer-reader trace",
      "stop_condition": "Stop when shared state path and consumer action are explicit.",
      "wave": 1,
      "owner_id": "hunter-state",
      "status": "covered",
      "outcome": "The same cache file links the writer and later request deserializer.",
      "evidence_ids": [
        "E000001"
      ],
      "candidate_ids": []
    }
  ],
  "coverage_reviews": [
    {
      "review_id": "CR1",
      "review_type": "post_wave",
      "wave": 1,
      "reviewer_id": "critic-wave-1",
      "independent": true,
      "scope_reviewed": "Cold-start pass over all four units; checked entry points to dangerous consumers, alternate protocol paths, cache lifecycle, and fixture exclusions.",
      "reviewed_coverage_ids": [
        "CU-a0c0d3a49b4cb1d37c9951b6",
        "CU-c028b875c47b01a4686e4a61",
        "CU-7919364f1cf0b876efad0a2e",
        "CU-9b8dd362eba2f2c4a06c4ca3"
      ],
      "decision": "clean",
      "new_coverage_ids": [],
      "evidence_ids": [
        "E000001",
        "E000002",
        "E000003",
        "E000005"
      ]
    },
    {
      "review_id": "CR2",
      "review_type": "final_clean",
      "wave": null,
      "reviewer_id": "critic-final-1",
      "independent": true,
      "scope_reviewed": "Independent final pass over the current source map and all four unit IDs, including both N/A searches, the callback chain, and the cross-request cache path.",
      "reviewed_coverage_ids": [
        "CU-a0c0d3a49b4cb1d37c9951b6",
        "CU-c028b875c47b01a4686e4a61",
        "CU-7919364f1cf0b876efad0a2e",
        "CU-9b8dd362eba2f2c4a06c4ca3"
      ],
      "decision": "clean",
      "new_coverage_ids": [],
      "evidence_ids": [
        "E000001",
        "E000002",
        "E000003",
        "E000005"
      ]
    }
  ],
  "candidate_reviews": [
    {
      "candidate_id": "C1",
      "claim": "The later request instantiates an object from cached plugin output when an untrusted plugin can supply an object return value.",
      "source_refs": [
        "fixtures/mini-poi/index.php:parse_page",
        "fixtures/mini-poi/index.php:mini_poi_serve_page",
        "fixtures/mini-poi/plugin.php:MiniPoiPlugin::handle"
      ],
      "verdict": "needs_validation",
      "verifier_id": "candidate-verifier-1",
      "independent": true,
      "reviewed_paths": [
        "fixtures/mini-poi/index.php",
        "fixtures/mini-poi/plugin.php"
      ],
      "disproof_attempt": "Checked the shipped plugin return and the cache read path; the checked-in implementation returns an array, but the mixed contract does not rule out alternate plugin implementations.",
      "unresolved": "The fixture does not establish that an attacker can install/control a plugin that returns an object, or that a usable gadget is loaded; retain as conditional and do not claim RCE.",
      "evidence_ids": [
        "E000001",
        "E000002"
      ]
    }
  ],
  "budget": {
    "unit": "bounded review passes",
    "max_units": 12,
    "spent_units": 9,
    "review_reserve_units": 2,
    "candidate_review_reserve_units": 1
  },
  "run_status": "incomplete",
  "incomplete_reasons": [
    "Candidate C1 still depends on an unverified attacker-controlled plugin implementation and an unverified loaded gadget; the fixture cannot establish either deployment precondition."
  ]
}
```
