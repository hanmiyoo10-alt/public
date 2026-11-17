#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

const SOURCE_REPO = 'hanmiyoo10-alt/-';
const POLICY_FILE = 'public-projection-policy.json';
const SHA_RE = /^[0-9a-f]{40}$/;

const EXPECTED_ENTRIES = Object.freeze([
  ['main', 'local/termux/00-update-local-stack', 'artifacts/termux/00-update-local-stack'],
  ['main', 'local/termux/10-start-local-stack', 'artifacts/termux/10-start-local-stack'],
  ['release-simcore', 'plugins/simcore/latest.js', 'artifacts/simcore/latest.js'],
  ['release-simcore', 'plugins/simcore/install.js', 'artifacts/simcore/install.js'],
  ['release-usage-dashboard', 'plugins/usage-dashboard/latest.js', 'artifacts/usage-dashboard/latest.js'],
  ['release-usage-dashboard', 'plugins/usage-dashboard/runtime/product-manifest.json', 'artifacts/usage-dashboard/runtime/product-manifest.json'],
  ['release-usage-dashboard', 'plugins/usage-dashboard/runtime/bridge-engine.mjs', 'artifacts/usage-dashboard/runtime/bridge-engine.mjs'],
  ['release-usage-dashboard', 'plugins/usage-dashboard/runtime/bridge-manager.cjs', 'artifacts/usage-dashboard/runtime/bridge-manager.cjs'],
  ['release-usage-dashboard', 'plugins/usage-dashboard/runtime/bootstrap-bridge-manager.sh', 'artifacts/usage-dashboard/runtime/bootstrap-bridge-manager.sh'],
]);

function fail(code, detail = '') {
  throw new Error(detail ? `${code}: ${detail}` : code);
}

function git(cwd, args, encoding = 'utf8') {
  return execFileSync('git', args, {
    cwd,
    encoding: encoding === null ? null : encoding,
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
  });
}

function gitText(cwd, args) {
  return String(git(cwd, args)).trim();
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function normalizeRemote(value) {
  const raw = String(value || '').trim().replace(/\.git$/, '').replace(/\/$/, '');
  if (raw.startsWith('git@github.com:')) return raw.slice('git@github.com:'.length);
  if (raw.startsWith('ssh://git@github.com/')) return raw.slice('ssh://git@github.com/'.length);
  if (raw.startsWith('https://github.com/')) return raw.slice('https://github.com/'.length);
  return raw;
}

function parseArgs(argv) {
  const out = {canonicalDir: null, repoDir: null};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg !== '--canonical-dir' && arg !== '--repo-dir') fail('ARGUMENT_INVALID', arg);
    const value = argv[i + 1];
    if (!value || value.startsWith('--')) fail('ARGUMENT_VALUE_MISSING', arg);
    if (arg === '--canonical-dir') out.canonicalDir = path.resolve(value);
    else out.repoDir = path.resolve(value);
    i += 1;
  }
  if (!out.canonicalDir || !out.repoDir) fail('ARGUMENT_REQUIRED');
  return out;
}

function loadPolicy(repoDir) {
  const policy = JSON.parse(fs.readFileSync(path.join(repoDir, POLICY_FILE), 'utf8'));
  if (policy?.schemaVersion !== 1
      || policy?.projectionVersion !== '1.0.0'
      || policy?.sourceRepository !== SOURCE_REPO
      || policy?.authority !== 'DERIVED_PUBLICATION_ONLY'
      || !Array.isArray(policy?.entries)) {
    fail('POLICY_HEADER_INVALID');
  }
  const actual = policy.entries.map(row => [row.ref, row.source, row.target]);
  if (JSON.stringify(actual) !== JSON.stringify(EXPECTED_ENTRIES)) fail('POLICY_ALLOWLIST_INVALID');
  return policy;
}

function sourceSha(canonicalDir, ref) {
  const sha = gitText(canonicalDir, ['rev-parse', '--verify', `refs/remotes/origin/${ref}^{commit}`]);
  if (!SHA_RE.test(sha)) fail('SOURCE_SHA_INVALID', ref);
  return sha;
}

function sourceMode(canonicalDir, sha, sourcePath) {
  const line = gitText(canonicalDir, ['ls-tree', sha, '--', sourcePath]);
  const match = line.match(/^(100644|100755)\s+blob\s+[0-9a-f]{40}\t/);
  if (!match) fail('SOURCE_MODE_INVALID', sourcePath);
  return match[1];
}

async function writeFileExact(filePath, bytes, mode) {
  await fsp.mkdir(path.dirname(filePath), {recursive: true});
  await fsp.writeFile(filePath, bytes);
  await fsp.chmod(filePath, mode === '100755' ? 0o755 : 0o644);
}

async function clearArtifacts(repoDir) {
  const root = path.join(repoDir, 'artifacts');
  await fsp.rm(root, {recursive: true, force: true});
  await fsp.mkdir(root, {recursive: true});
}

async function main() {
  const {canonicalDir, repoDir} = parseArgs(process.argv.slice(2));
  const policy = loadPolicy(repoDir);
  const remote = normalizeRemote(gitText(canonicalDir, ['config', '--get', 'remote.origin.url']));
  if (remote !== SOURCE_REPO) fail('SOURCE_REPOSITORY_MISMATCH', remote);

  const refs = {};
  for (const ref of [...new Set(policy.entries.map(row => row.ref))]) refs[ref] = sourceSha(canonicalDir, ref);

  await clearArtifacts(repoDir);
  const projected = [];
  for (const row of policy.entries) {
    const sha = refs[row.ref];
    const bytes = git(canonicalDir, ['show', `${sha}:${row.source}`], null);
    const mode = sourceMode(canonicalDir, sha, row.source);
    await writeFileExact(path.join(repoDir, row.target), bytes, mode);
    projected.push({
      sourceRef: row.ref,
      sourceCommit: sha,
      sourcePath: row.source,
      publicPath: row.target,
      mode,
      size: bytes.length,
      sha256: sha256(bytes),
    });
  }

  const provenance = {
    schemaVersion: 1,
    projectionVersion: policy.projectionVersion,
    authority: 'DERIVED_PUBLICATION_ONLY',
    sourceRepository: SOURCE_REPO,
    sourceRefs: refs,
    files: projected,
  };
  const provenanceBytes = Buffer.from(JSON.stringify(provenance, null, 2) + '\n');
  await writeFileExact(path.join(repoDir, 'artifacts/provenance.json'), provenanceBytes, '100644');
  process.stdout.write(JSON.stringify({
    status: 'PASS',
    sourceRefs: refs,
    projectedFiles: projected.length,
    provenanceSha256: sha256(provenanceBytes),
  }) + '\n');
}

main().catch(error => {
  process.stderr.write(String(error?.message || error) + '\n');
  process.exitCode = 1;
});
