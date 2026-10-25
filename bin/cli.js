#!/usr/bin/env node
'use strict';

/**
 * mini-adjudication installer.
 *
 * Copies the skill payload into the agent skill directories and writes
 * the /adjudicate trigger command. Zero dependencies; stdlib only.
 *
 * The skill payload is byte-exact: runtime/skill_manifest.json carries
 * sha256 hashes of every tracked file, and the byte-exactness is what
 * makes `check_skill_loaded.py` pass on the installed copy. Copy (the
 * default) preserves bytes on every platform; --link is a convenience
 * for working from a checkout and is refused from inside node_modules
 * (an npx cache is ephemeral and would leave a dangling link).
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const PKG_ROOT = path.resolve(__dirname, '..');
const SKILL_NAME = 'mini-adjudication';
const PAYLOAD = [
  'SKILL.md',
  'README.md',
  'references',
  'templates',
  'schemas',
  'runtime',
  'fixtures',
  '_meta.json',
];
const COMMAND_ASSET = path.join(PKG_ROOT, 'cli', 'commands', 'adjudicate.md');

const SKILL_ROOTS = {
  user: () => path.join(os.homedir(), '.agents', 'skills'),
  zcode: () => path.join(os.homedir(), '.zcode', 'skills'),
  claude: () => path.join(os.homedir(), '.claude', 'skills'),
};
const COMMAND_ROOTS = {
  user: () => path.join(os.homedir(), '.zcode', 'commands'),
  zcode: () => path.join(os.homedir(), '.zcode', 'commands'),
  claude: () => path.join(os.homedir(), '.claude', 'commands'),
};
const MARKER = SKILL_NAME;

function help() {
  console.log(`mini-adjudication — post-audit vulnerability acceptance standard (agent skill)

Usage:
  npx mini-adjudication install [scopes] [options]
  mini-adjudication update     [...]   alias of install (idempotent)
  mini-adjudication uninstall  [scopes]
  mini-adjudication doctor             verify installs, hashes, validator
  mini-adjudication help

Scopes (default: user):
  --user    ~/.agents/skills  + ~/.zcode/commands/adjudicate.md   (ZCode & friends)
  --zcode   ~/.zcode/skills   (same command file as --user)
  --claude  ~/.claude/skills  + ~/.claude/commands/adjudicate.md  (Claude Code)
  --all     all of the above

Options:
  --link   link to this package instead of copying (checkouts only; falls
           back to copy from an npx/npm cache, where links would dangle)

The skill itself needs Python 3 on PATH for its validator and evidence
ledger; the installer works without it (doctor reports python status).
`);
}

function parseArgs(argv) {
  const scopes = new Set();
  let link = false;
  for (const a of argv) {
    if (a === '--user') scopes.add('user');
    else if (a === '--zcode') scopes.add('zcode');
    else if (a === '--claude') scopes.add('claude');
    else if (a === '--all') { scopes.add('user'); scopes.add('zcode'); scopes.add('claude'); }
    else if (a === '--link') link = true;
    else if (a.startsWith('--')) { console.error(`unknown option: ${a}`); process.exit(2); }
  }
  if (scopes.size === 0) scopes.add('user');
  return { scopes: [...scopes], link };
}

function removePath(dest) {
  let st;
  try {
    st = fs.lstatSync(dest);
  } catch {
    return;
  }
  if (st.isSymbolicLink()) fs.unlinkSync(dest);
  else fs.rmSync(dest, { recursive: true, force: true });
}

function installPayload(dest, link) {
  removePath(dest);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const inCache = PKG_ROOT.includes(`${path.sep}node_modules${path.sep}`);
  if (link && inCache) {
    console.log(`  --link ignored inside an npm cache; copying instead`);
    link = false;
  }
  if (link) {
    try {
      const type = process.platform === 'win32' ? 'junction' : 'dir';
      fs.symlinkSync(PKG_ROOT, dest, type);
      console.log(`  linked  ${dest} -> ${PKG_ROOT}`);
      return;
    } catch (err) {
      console.log(`  link failed (${err.code || err.message}); copying instead`);
    }
  }
  fs.cpSync(PKG_ROOT, dest, {
    recursive: true,
    force: true,
    filter: (src) => {
      const rel = path.relative(PKG_ROOT, src);
      if (!rel) return true;
      const top = rel.split(path.sep)[0];
      return PAYLOAD.includes(top);
    },
  });
  console.log(`  copied  ${dest}`);
}

function renderCommand(skillDir) {
  const template = fs.readFileSync(COMMAND_ASSET, 'utf8');
  return template.split('{{SKILL_DIR}}').join(skillDir);
}

function writeCommand(scope) {
  const dir = COMMAND_ROOTS[scope]();
  const dest = path.join(dir, 'adjudicate.md');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(dest, renderCommand(path.join(SKILL_ROOTS[scope](), SKILL_NAME)));
  console.log(`  command ${dest}`);
  return dest;
}

function installedSkillDirs(scopes) {
  const found = [];
  for (const scope of scopes) {
    const dest = path.join(SKILL_ROOTS[scope](), SKILL_NAME);
    if (fs.existsSync(path.join(dest, 'SKILL.md'))) found.push({ scope, dest });
  }
  return found;
}

function pythonBin() {
  for (const bin of ['python', 'python3']) {
    const r = spawnSync(bin, ['--version'], { encoding: 'utf8' });
    if (!r.error && r.status === 0) return bin;
  }
  return null;
}

function run(py, script, args, label, failures) {
  const r = spawnSync(py, [script, ...args], { encoding: 'utf8' });
  const ok = !r.error && r.status === 0;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) {
    failures.push(label);
    const out = ((r.stdout || '') + (r.stderr || '')).trim();
    if (out) console.log(out.split('\n').slice(0, 12).map((l) => '        ' + l).join('\n'));
  }
}

function cmdInstall(argv) {
  const { scopes, link } = parseArgs(argv);
  console.log(`Installing ${SKILL_NAME} (scopes: ${scopes.join(', ')}):`);
  const writtenCommands = new Set();
  for (const scope of scopes) {
    installPayload(path.join(SKILL_ROOTS[scope](), SKILL_NAME), link);
    const cmdDir = COMMAND_ROOTS[scope]();
    if (!writtenCommands.has(cmdDir)) {
      writtenCommands.add(cmdDir);
      writeCommand(scope);
    }
  }
  console.log(`
Done. Open a new agent session, then: /adjudicate <findings.json>
(or trigger by phrasing like "审计出漏洞了，哪些能报").`);
}

function cmdUninstall(argv) {
  const { scopes } = parseArgs(argv);
  for (const scope of scopes) {
    const dest = path.join(SKILL_ROOTS[scope](), SKILL_NAME);
    if (fs.existsSync(dest)) {
      removePath(dest);
      console.log(`  removed ${dest}`);
    }
    const cmd = path.join(COMMAND_ROOTS[scope](), 'adjudicate.md');
    if (fs.existsSync(cmd) && fs.readFileSync(cmd, 'utf8').includes(MARKER)) {
      fs.rmSync(cmd);
      console.log(`  removed ${cmd}`);
    }
  }
}

function cmdDoctor() {
  const scopes = ['user', 'zcode', 'claude'];
  const found = installedSkillDirs(scopes);
  const failures = [];
  console.log(`mini-adjudication doctor:`);
  if (found.length === 0) {
    console.log('  FAIL  no installation found (run: npx mini-adjudication install)');
    failures.push('no installation');
  }
  for (const { scope, dest } of found) {
    console.log(`  OK    skill installed (${scope}): ${dest}`);
  }
  const py = pythonBin();
  if (!py) {
    console.log('  FAIL  python not on PATH (the validator and evidence ledger need it)');
    failures.push('python');
  }
  for (const { dest } of found) {
    if (!py) break;
    run(py, path.join(dest, 'runtime', 'check_skill_loaded.py'), [], `manifest hashes match (${path.basename(path.dirname(dest))})`, failures);
    run(
      py,
      path.join(dest, 'runtime', 'validate_adjudication.py'),
      [
        path.join(dest, 'fixtures', 'mini-adjudication', 'expected', 'adjudication-notes.md'),
        '--evidence-ledger',
        path.join(dest, 'fixtures', 'mini-adjudication', 'expected', 'evidence.jsonl'),
      ],
      `fixture validates structurally`,
      failures
    );
  }
  for (const cmd of [path.join(os.homedir(), '.zcode', 'commands', 'adjudicate.md'), path.join(os.homedir(), '.claude', 'commands', 'adjudicate.md')]) {
    if (fs.existsSync(cmd)) console.log(`  OK    trigger command: ${cmd}`);
  }
  if (failures.length) {
    console.log(`\nFAIL: ${failures.length} check(s) failed`);
    return 1;
  }
  console.log(`\nOK: all checks passed`);
  return 0;
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case 'install':
    case 'update':
      cmdInstall(rest);
      return 0;
    case 'uninstall':
      cmdUninstall(rest);
      return 0;
    case 'doctor':
      return cmdDoctor();
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      help();
      return 0;
    default:
      console.error(`unknown command: ${cmd}\n`);
      help();
      return 2;
  }
}

process.exit(main());
