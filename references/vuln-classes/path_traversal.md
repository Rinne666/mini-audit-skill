# Path Traversal

The attacker reaches a file-system operation with a path whose
segments the application does not control. Classic traversal
(`../`), URL-encoded (`%2e%2e%2f`), null-byte truncation, symlink
follow, absolute path injection.

## Where to look

- File serving endpoints: `sendFile`, `static`, `send_file`,
  `sendFromDirectory`, `FileResponse`, `Image.open`.
- File write endpoints: upload handlers, file write APIs,
  template loaders, log writers, cache writers.
- Include/require: PHP `include`, Python `open()`, Node
  `fs.readFile`, template engine `render` with attacker
  template name.
- Archive extraction: ZIP/TAR extractors without path
  normalization (zip-slip).
- Path joins that do not canonicalize: `os.path.join` is not
  safe with absolute second arguments.

## Disproofs that often fail

- "We strip `../`." The attacker encodes it. Read the
  stripping function — does it apply before or after URL
  decoding? Does it handle `..%2f` and `%2e%2e%2f`?
- "We restrict to a base directory and then open." Read the
  canonicalization. Without `realpath` + base prefix check,
  the base is not enforced.
- "It's a static file server." Static servers often have a
  configured base, but the symlink-follow and zip-slip classes
  happen *outside* the base.

## The permission delta

Read of arbitrary files → high (config, secrets, source).
Write to arbitrary paths → critical (webshell, persistence).
Execution via template include → critical.

The severity also depends on what is reachable. On a
containerized workload with no secrets on disk, arbitrary
read drops to medium. On a host with the application
configuration, SSH keys, or service credentials, arbitrary
read is high and arbitrary write is critical.