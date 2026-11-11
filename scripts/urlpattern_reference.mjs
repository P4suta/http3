// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Offline generation: node scripts/urlpattern_reference.mjs --write INPUT_DIR
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const [mode, directory] = process.argv.slice(2);
assert(['--write', '--check'].includes(mode) && directory);
assert.equal(process.version, 'v26.8.2');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(readFileSync('LICENSES/Unicode-3.0.txt')),
  'e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96');
assert.equal(sha(readFileSync('LICENSES/BSD-3-Clause.txt')),
  '5fac07febb0e2a97fb0d7b0def149ec08b642e1ba4b9c345283ab1cbd2af6570');
const inputs = {
  specification: ['urlpattern-696b402.html', 'e93fd5310a762a3835f256aa6c1b076634f57c1ef5bd170fb9a8ffabc7fea936'],
  correction: ['urlpattern-aeb2019.html', 'f2392c3bad5ccb3b253cfcebdb98f16abb12c4669c578396dd7ab518957a9d87'],
  unicode: ['DerivedCoreProperties-16.0.0.txt', '39d35161f2954497f69e08bdb9e701493f476a3d30222de20028feda36c1dabd'],
  wpt: ['wpt-0c1d195.json', 'db329f22a3fc666bdf85d20856cf32d1074f4e7f9b30c05ead596463cdb2f734'],
};
const loaded = {};
for (const [name, [path, digest]] of Object.entries(inputs)) {
  assert(statSync(join(directory, path)).size < 2_097_152);
  const bytes = readFileSync(join(directory, path));
  assert.equal(sha(bytes), digest);
  loaded[name] = bytes.toString('utf8');
}
const binary = readFileSync(process.execPath);
assert.equal(sha(binary), '8a22a371fd85aecf5411636574309f6380fbc42694aaf0651a089a8ef9c44e52');
const ranges = property => {
  const rows = [];
  for (const line of loaded.unicode.split('\n')) {
    const match = /^([0-9A-F]+)(?:\.\.([0-9A-F]+))?\s*;\s*(ID_Start|ID_Continue)\s*#/.exec(line);
    if (!match || match[3] !== property) continue;
    const first = Number.parseInt(match[1], 16), last = Number.parseInt(match[2] || match[1], 16);
    assert(first >= 0 && first <= last && last <= 0x10ffff);
    const previous = rows.at(-1);
    assert(!previous || previous[1] < first);
    if (previous && previous[1] + 1 === first) previous[1] = last;
    else rows.push([first, last]);
  }
  assert(rows.length > 500 && rows.length < 1000);
  return rows;
};
const table = (name, rows) => {
  const cells = rows.flatMap(([first, last]) => [first, last]);
  const lines = [];
  for (let i = 0; i < cells.length; i += 6) {
    lines.push('  ' + cells.slice(i, i + 6).map(v => v + ':32').join(', ') + ',');
  }
  return `const ${name} = <<\n${lines.join('\n')}\n>>\n`;
};
const starts = ranges('ID_Start'), continues = ranges('ID_Continue');
const unformattedSource = `//// Generated Unicode 16.0 identifier property ranges; do not hand edit.
//// SPDX-FileCopyrightText: 2024 Unicode®, Inc.
//// SPDX-FileCopyrightText: 2026 the http contributors
//// SPDX-License-Identifier: Unicode-3.0 AND (MIT OR Apache-2.0)
//// Source SHA256 ${inputs.unicode[1]}.
//// The generator pins all input bytes and the Node reference executable.

import gleam/bool

${table('starts', starts)}
${table('continues', continues)}
pub fn id_start(code: Int) -> Bool {
  contains(ranges: starts, code:, low: 0, high: ${starts.length})
}

pub fn id_continue(code: Int) -> Bool {
  contains(ranges: continues, code:, low: 0, high: ${continues.length})
}

fn contains(ranges ranges: BitArray, code code: Int, low low: Int, high high: Int) -> Bool {
  use <- bool.guard(low >= high, False)
  let middle = low + { high - low } / 2
  let skipped = middle * 64
  case ranges {
    <<_:size(skipped), first:32, last:32, _:bits>> -> case code {
      value if value < first -> contains(ranges:, code:, low:, high: middle)
      value if value > last -> contains(ranges:, code:, low: middle + 1, high:)
      _ -> True
    }
    _ -> False
  }
}
`;
const formatter = '/usr/local/bin/gleam';
const formatterHash = '2d48c70edb9da6181224b82050179da9112bc42d7e374360475dc18109762a0e';
assert.equal(sha(readFileSync(formatter)), formatterHash);
const source = execFileSync(formatter, ['format', '--stdin'], {
  input: unformattedSource, encoding: 'utf8', timeout: 10_000, maxBuffer: 262_144,
  windowsHide: true,
});
assert.equal(sha(readFileSync(formatter)), formatterHash);
const all = JSON.parse(loaded.wpt), vectors = [];
for (let index = 0; index < all.length; index++) {
  const row = all[index];
  if (!Array.isArray(row.pattern) || row.pattern.length !== 1 ||
      !row.pattern[0] || typeof row.pattern[0] !== 'object' ||
      Object.keys(row.pattern[0]).join(',') !== 'pathname') continue;
  const pattern = row.pattern[0].pathname;
  if (typeof pattern !== 'string') continue;
  let compiled;
  try { compiled = new URLPattern(...row.pattern); } catch {
    assert.equal(row.expected_obj, 'error');
    vectors.push({ index, pattern, input: '', valid: false, matched: false });
    continue;
  }
  assert.notEqual(row.expected_obj, 'error');
  if (compiled.hasRegExpGroups || !Array.isArray(row.inputs) || row.inputs.length !== 1 ||
      !row.inputs[0] || typeof row.inputs[0] !== 'object' ||
      Object.keys(row.inputs[0]).join(',') !== 'pathname' || typeof row.inputs[0].pathname !== 'string') continue;
  const matched = compiled.test(...row.inputs);
  assert.equal(matched, row.expected_match !== null);
  vectors.push({ index, pattern, input: row.inputs[0].pathname, valid: true, matched });
}
assert.equal(vectors.length, 136);
const fixture = {
  schema: 1,
  scope: 'Selected pathname-only WPT components without regexp groups; not complete URL constructor qualification.',
  specification: 'https://urlpattern.spec.whatwg.org/commit-snapshots/696b4029d52e5854044bac6b72cdb198cb962ed0/',
  wpt_revision: '0c1d19546fd4873bb9f4147f0bbf868e7b4f91b7',
  wpt_sha256: inputs.wpt[1],
  license: 'BSD-3-Clause',
  copyright: 'web-platform-tests contributors',
  reference: { name: 'Node.js URLPattern', version: process.version, binary_sha256: sha(binary) },
  vectors,
};
const constructorVectors = [], constructorDifferences = [];
for (let index = 0; index < all.length; index++) {
  const row = all[index];
  if (!Array.isArray(row.pattern) || typeof row.pattern[0] !== 'string' || row.pattern.length > 2) continue;
  const pattern = row.pattern[0], base = row.pattern[1] ?? 'https://dictionary.invalid/';
  if (typeof base !== 'string' || !/^https?:/i.test(base)) continue;
  try { new URL(base); } catch { continue; }
  if (row.pattern.length === 1 && !/^https?:/i.test(pattern)) continue;
  let compiled;
  try { compiled = new URLPattern(...row.pattern); } catch {
    assert.equal(row.expected_obj, 'error');
    constructorVectors.push({ index, pattern, base, input: '', valid: false, matched: false });
    continue;
  }
  if (row.expected_obj === 'error') {
    constructorDifferences.push({ index, expected: 'constructor_rejected', observed: 'constructor_accepted' });
    continue;
  }
  if (compiled.hasRegExpGroups || !Array.isArray(row.inputs) || typeof row.inputs[0] !== 'string' || row.inputs.length > 2) continue;
  let candidate;
  try { candidate = new URL(...row.inputs); } catch { continue; }
  if (!['http:', 'https:'].includes(candidate.protocol)) continue;
  assert(Object.hasOwn(row, 'expected_match'));
  const matched = compiled.test(...row.inputs);
  assert.equal(matched, row.expected_match !== null);
  constructorVectors.push({ index, pattern, base, input: candidate.href, valid: true, matched });
}
assert.equal(constructorVectors.length, 33);
assert.deepEqual(constructorDifferences, [{ index: 222, expected: 'constructor_rejected', observed: 'constructor_accepted' }]);
const constructorFixture = { ...fixture,
  scope: 'HTTP(S) constructor WPT cases where the pinned WPT and independent Node agree; disagreement is retained separately, not a passing requirement.',
  correction_specification: 'https://urlpattern.spec.whatwg.org/commit-snapshots/aeb2019cf3aa1fb31af134a682c0255302a41297/',
  correction_sha256: inputs.correction[1],
  vectors: constructorVectors, reference_disagreements: constructorDifferences,
};
const outputs = [
  ['src/http/internal/url_pattern/unicode.gleam', source],
  ['test/fixtures/urlpattern-wpt.json', JSON.stringify(fixture, null, 2) + '\n'],
  ['test/fixtures/urlpattern-constructor-wpt.json', JSON.stringify(constructorFixture, null, 2) + '\n'],
];
for (const [path, text] of outputs) {
  if (mode === '--check') assert.equal(readFileSync(path, 'utf8'), text);
  else writeFileSync(path, text);
}
console.log(JSON.stringify({ unicode_start_ranges: starts.length, unicode_continue_ranges: continues.length,
  vectors: vectors.length, constructor_vectors: constructorVectors.length, reference_disagreements: constructorDifferences.length, formatter_sha256: formatterHash,
  outputs: outputs.map(([path, bytes]) => ({ path, sha256: sha(bytes) })) }));
