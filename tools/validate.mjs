#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import {execFileSync} from 'node:child_process';

const ROOT = path.resolve(new URL('..', import.meta.url).pathname);
const POLICY_PATH = path.join(ROOT, 'public-projection-policy.json');
const PROVENANCE_PATH = path.join(ROOT, 'artifacts/provenance.json');
const SHA_RE = /^[0-9a-f]{40}$/;
const DIGEST_RE = /^[0-9a-f]{64}$/;

function fail(code, detail = '') {
  throw new Error(detail ? `${code}: ${detail}` : code);
}
function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}
function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
async function walk(dir, rel = '') {
  const rows = [];
  for (const entry of await fsp.readdir(dir, {withFileTypes: true})) {
    const next = rel ? `${rel}/${entry.name}` : entry.name;
    const abs = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) fail('SYMLINK_FORBIDDEN', next);
    if (entry.isDirectory()) rows.push(...await walk(abs, next));
    else if (entry.isFile()) rows.push(next);
  }
  return rows.sort();
}
function trackedFiles() {
  const out = execFileSync('git', ['ls-files', '-s', '-z'], {cwd: ROOT, encoding: 'utf8'});
  return out.split('\0').filter(Boolean).map(record => {
    const match = record.match(/^([0-9]{6}) [0-9a-f]{40} [0-3]\t(.+)$/s);
    if (!match) fail('TRACKED_INDEX_RECORD_INVALID');
    return {mode: match[1], file: match[2]};
  });
}
function scanSecrets() {
  const forbidden = [
    /-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----/,
    /github_pat_[A-Za-z0-9_]{20,}/,
    /gh[pousr]_[A-Za-z0-9]{20,}/,
    /AKIA[0-9A-Z]{16}/,
  ];
  for (const {mode, file} of trackedFiles()) {
    if (mode === '120000') fail('TRACKED_SYMLINK_FORBIDDEN', file);
    if (mode !== '100644' && mode !== '100755') fail('TRACKED_MODE_FORBIDDEN', file + ':' + mode);
    const abs = path.join(ROOT, file);
    const fd = fs.openSync(abs, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile()) fail('TRACKED_NON_FILE_FORBIDDEN', file);
      if (stat.size > 8 * 1024 * 1024) continue;
      const text = fs.readFileSync(fd, 'utf8');
      if (forbidden.some(re => re.test(text))) fail('POSSIBLE_SECRET_MATERIAL', file);
    } finally {
      fs.closeSync(fd);
    }
  }
}
async function main() {
  const policy = loadJson(POLICY_PATH);
  const provenance = loadJson(PROVENANCE_PATH);
  if (policy.schemaVersion !== 1 || policy.sourceRepository !== 'hanmiyoo10-alt/-'
      || policy.authority !== 'DERIVED_PUBLICATION_ONLY' || !Array.isArray(policy.entries)) {
    fail('POLICY_INVALID');
  }
  if (provenance.schemaVersion !== 1 || provenance.projectionVersion !== policy.projectionVersion
      || provenance.authority !== 'DERIVED_PUBLICATION_ONLY'
      || provenance.sourceRepository !== policy.sourceRepository
      || !Array.isArray(provenance.files)) fail('PROVENANCE_INVALID');
  const expectedPaths = policy.entries.map(row => row.target).concat(['artifacts/provenance.json']).sort();
  const actualPaths = (await walk(path.join(ROOT, 'artifacts'))).map(p => `artifacts/${p}`).sort();
  if (JSON.stringify(actualPaths) !== JSON.stringify(expectedPaths)) {
    fail('ARTIFACT_INVENTORY_MISMATCH', JSON.stringify({expectedPaths, actualPaths}));
  }
  if (provenance.files.length !== policy.entries.length) fail('PROVENANCE_FILE_COUNT_INVALID');
  for (let i = 0; i < policy.entries.length; i += 1) {
    const p = policy.entries[i];
    const r = provenance.files[i];
    if (r.sourceRef !== p.ref || r.sourcePath !== p.source || r.publicPath !== p.target) {
      fail('PROVENANCE_MAPPING_MISMATCH', p.target);
    }
    if (!SHA_RE.test(r.sourceCommit) || provenance.sourceRefs?.[p.ref] !== r.sourceCommit) {
      fail('PROVENANCE_SOURCE_SHA_INVALID', p.target);
    }
    if (!['100644','100755'].includes(r.mode) || !Number.isInteger(r.size) || r.size < 0 || !DIGEST_RE.test(r.sha256)) {
      fail('PROVENANCE_FILE_METADATA_INVALID', p.target);
    }
    const bytes = fs.readFileSync(path.join(ROOT, p.target));
    if (bytes.length !== r.size || sha256(bytes) !== r.sha256) fail('ARTIFACT_DIGEST_MISMATCH', p.target);
    const mode = (fs.statSync(path.join(ROOT, p.target)).mode & 0o111) ? '100755' : '100644';
    if (mode !== r.mode) fail('ARTIFACT_MODE_MISMATCH', p.target);
  }
  scanSecrets();
  process.stdout.write(JSON.stringify({
    status:'PASS',
    artifactCount:policy.entries.length,
    sourceRefs:provenance.sourceRefs,
    secretScan:'PASS',
  }) + '\n');
}
main().catch(error => {
  process.stderr.write(String(error?.message || error) + '\n');
  process.exitCode = 1;
});
