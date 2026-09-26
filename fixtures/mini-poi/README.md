# Mini-POI fixture

A minimal PHP target that exhibits the deserialization
object-injection shape that the DokuWiki 2026-07-14a audit
uncovered (Issue #4752, CWE-502).

The shape:

- `index.php` parses page text. Lines matching `!plugin! ...`
  are routed to the plugin's `handle()`.
- `plugin.php` returns whatever the plugin wants.
- The application calls `serialize()` on the parser calls
  (which include the plugin's return value) and writes them
  to a cache file.
- A separate request path calls `unserialize()` on the cache
  file. There is no `[allowed_classes => false]` filter.

If the plugin's `handle()` returns an object, that object
ends up in the cache file. The next `unserialize()` call
instantiates it and runs `__wakeup`.

The fixture is intentionally tiny. The bug shape is the
point; the rest of the application is elided.

## What a correct audit produces

The expected output of a correct audit on this fixture lives
in `expected/`:

- `expected/notes.md` -- the audit notes file with a valid
  pairing table and Coverage paragraph.
- `expected/finding.md` -- the finding file describing the
  POI.

`runtime/regression.py` runs the two enforcement primitives
(validate-notes + check-skill-loaded) against `expected/`.
The regression passes when both pass.

The fixture is not a substitute for an LLM-in-the-loop audit
trial. It locks the output format the audit must produce; it
does not prove the LLM produces that output. The trial is
out-of-band.
