# Deserialization

A deserialization bug is one of the most consistently critical bug
classes because the attacker's input is the code. Languages where
this is live today: Java (ObjectInputStream), Python (pickle,
PyYAML.load), PHP (unserialize), .NET (BinaryFormatter), Node
(`node-serialize`, `js-yaml.load`), Ruby (Marshal), Go
(`encoding/gob`).

## The shape

1. The application deserializes attacker-controlled bytes into
   live objects.
2. The deserialization format allows either gadget chains (Java,
   .NET, PHP) or direct code execution primitives (Python pickle,
   Ruby Marshal, PyYAML unsafe load).
3. No integrity check (HMAC, signature, schema) sits between the
   bytes and the live objects.

## Where to look

- Any handler that accepts a serialized blob (binary body,
  base64 in a header, cookie value, JWT, message queue payload).
- Any cache or session store whose contents are deserialized on
  read.
- Configuration loaders that deserialize from external sources.
- Any usage of a known-dangerous loader: `pickle.loads`,
  `yaml.load` without `Loader=SafeLoader`, `unserialize`,
  `BinaryFormatter.Deserialize`, `Marshal.load`,
  `node-serialize`.

## Disproofs that often fail

- "We use a safe loader." Read the loader. `yaml.load` defaults
  are unsafe; `yaml.safe_load` is the right answer.
- "The input is signed." The signer is the same service that
  reads the data, so the signature gates nothing.
- "There are no gadgets in our classpath." A short audit is not
  proof of no gadgets. Treat the deserialization itself as the
  vulnerability.
- "It's only reachable from a trusted source." Trace the bytes
  back to the attacker. If they come from the user, the audit is
  not done.

## The permission delta

Deserialization almost always produces remote code execution
(RCE). Severity is critical if reachable from an untrusted
network path; high if reachable only after authentication;
medium if only reachable from an internal network with no
exploit chain to a privileged account.