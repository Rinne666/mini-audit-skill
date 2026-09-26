# Finding -- mini-poi deserialization object injection

> Reference finding for the mini-poi fixture. The fixture is
> an illustrative reproduction of DokuWiki Issue #4752
> (CWE-502), not a real advisory.

## Summary

A user with permission to publish page text can have a
plugin's `handle()` method return an arbitrary object. That
object is `serialize()`-ed into a cache file and
`unserialize()`-d by the next request to serve the page.
Without `[allowed_classes => false]`, the object is fully
instantiated and `__wakeup` runs, achieving arbitrary code
execution on the server.

## Severity

`critical` -- arbitrary code execution under the user
context of the web server. Reachable from any role allowed
to edit a page containing the `!plugin!` marker.

## Location

- `fixtures/mini-poi/index.php:38` -- `serialize($parser_calls)`.
- `fixtures/mini-poi/index.php:43` -- `unserialize(...)`.
- `fixtures/mini-poi/plugin.php:13` -- untyped `handle()` return.

## Preconditions

- Attacker state: any role with edit permission on a page.
- System state: standard deployment of mini-poi; no special
  configuration required.

## Attack path

1. Attacker installs or modifies a plugin whose `handle()`
   returns an object with a `__wakeup` that does something
   dangerous. (`fixtures/mini-poi/plugin.php:13` has no
   return-type contract; the application does not constrain
   it.)
2. Attacker edits a page containing `!plugin! <anything>`.
   `index.php:23` routes the line to `MiniPoiPlugin::handle()`.
3. `index.php:38` `serialize()`s the parser-calls array --
   which contains the plugin's return value -- into the
   cache file.
4. Any subsequent page render reads the cache file and
   `unserialize()`s it (`index.php:43`). The object is
   instantiated; `__wakeup` runs.
5. Server is now running attacker code under the web-server
   user.

## Evidence

- `fixtures/mini-poi/index.php:38` -- `serialize($parser_calls)`
  with no type filter.
- `fixtures/mini-poi/index.php:43` -- `unserialize(...)` with
  no `[allowed_classes => false]`.
- Static end-to-end proof: attacker controls
  `MiniPoiPlugin::handle()` return value -> serialized into
  cache -> unserialized in next request.

## Why existing controls missed it

The application assumed the plugin's `handle()` returns a
plain instruction (string / array). It never validated that
assumption. The cache file was treated as opaque bytes
inside its own trust boundary, but the plugin API broke
that boundary by allowing attacker-controlled object
shapes into the serialized bytes.

## Remediation

- Add `[allowed_classes => false]` to the `unserialize()`
  call at `fixtures/mini-poi/index.php:43`. This rejects
  every object on the read path regardless of who wrote
  it.
- Add a return-type contract to `MiniPoiPlugin::handle()`
  -- `array<string, mixed>` is enough -- and validate at
  the call site (`index.php:30`).