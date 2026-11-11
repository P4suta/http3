// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Offline pinned reference generation; no runtime network or production FFI.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { domainToASCII } from 'node:url';
import assert from 'node:assert/strict';

const [mode, directory, destination = 'test/fixtures/url-host-reference.json'] = process.argv.slice(2);
assert(['--write', '--check'].includes(mode) && directory);
assert.equal(process.version, 'v26.8.2');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
assert.equal(sha(readFileSync(process.execPath)), '8a22a371fd85aecf5411636574309f6380fbc42694aaf0651a089a8ef9c44e52');
const inputs = {
  idna: ['IdnaTestV2.txt', 'ffcf59f6e97d765caa5ac8315e9511ba3b42955a554cbc431e4c016f20d25ca9'],
  nfc: ['NormalizationTest.txt', 'd811971453e7075e1ad56fb1b301eece5aa80757b81f6156e74a1bfb3ae5ceb1'],
  url: ['url-standard.html', '8e2eef304c23375141e1ac38268d5b5a54eff934c14c3175b323aab419b0dfbe'],
};
const loaded = {};
for (const [name, [file, hash]] of Object.entries(inputs)) {
  const path = join(directory, file);
  assert(statSync(path).size <= 4_194_304);
  const bytes = readFileSync(path);
  assert.equal(sha(bytes), hash);
  loaded[name] = bytes.toString('utf8');
}
const unescape = value => value.replace(/\\u\{([0-9a-f]+)\}|\\u([0-9a-f]{4})|\\x\{([0-9a-f]+)\}/giu,
  (_, a, b, c) => String.fromCodePoint(parseInt(a || b || c, 16)));
const scalars = value => [...value].every(c => c.codePointAt(0) < 0xd800 || c.codePointAt(0) > 0xdfff);
const hostInputs = new Set([
  '', '.', '..', 'EX%41MPLE.com.', 'foo_bar.example', '-a..b-', 'a/b', 'a:b', 'a@b', 'a\\b',
  'a b', 'a\tb', '%', '%ff', '%c0%af', 'x%23y', 'a%00b', 'faß.de', 'ＦＡＳＳ。de', '①.②.③.④',
  'xn--', 'xn--8i7caa', 'xn--a-', 'xn--a-。example', 'xn--\u00e9.example',
  'a'.repeat(2048), 'a'.repeat(2049), 'a'.repeat(2046) + 'é',
]);
const ordinary = new Set(hostInputs);
const idna = [];
let skippedIllFormed = 0;
for (const line of loaded.idna.split('\n')) {
  const columns = line.split('#', 1)[0].split(';').map(s => s.trim());
  if (columns.length < 7) continue;
  const source = columns[0] === '""' ? '' : unescape(columns[0]);
  const unicode = columns[1] ? (columns[1] === '""' ? '' : unescape(columns[1])) : source;
  const ascii = columns[3] ? (columns[3] === '""' ? '' : unescape(columns[3])) : unicode;
  const statuses = (columns[4] || columns[2]).replace(/[\[\]\s]/gu, '').split(',').filter(Boolean);
  const errors = statuses.filter(value => !['A4_1', 'A4_2', 'V2', 'V3', 'U1'].includes(value));
  if (scalars(source)) idna.push({ index: idna.length, input: [...source].map(c => c.codePointAt(0)), output: errors.length ? null : ascii });
  else ++skippedIllFormed;
  for (const index of [0, 1, 3]) {
    const input = unescape(columns[index]);
    if (scalars(input) && Buffer.byteLength(input) <= 2048) hostInputs.add(input);
  }
}
for (const a of ['0', '1', '255', '256', '65535', '65536', '16777215', '16777216', '4294967295', '4294967296', '00', '09', '0x', '0xff', '0XFFFFFFFF', '0123', '+1', '1e2']) {
  for (const prefix of ['', '1.', '1.2.', '1.2.3.', 'name.']) {
    ordinary.add(prefix + a); ordinary.add(prefix + a + '.');
  }
}
for (let mask = 0; mask < 256; ++mask) {
  const parts = Array.from({ length: 8 }, (_, i) => mask & (1 << i) ? '0' : (i + 1).toString(16));
  ordinary.add('[' + parts.join(':') + ']');
}
for (const value of ['::', '::1', '1::', ':1', '1:', '1::2::3', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9',
  '::ffff:192.0.2.128', '::ffff:192.00.2.1', '::ffff:192.0.2', '::ffff:256.1.2.3',
  '192.0.2.1::', '1:2:3:4:5:6:192.0.2.1', 'fe80::1%25eth0']) ordinary.add('[' + value + ']');
const reference = input => {
  if (!input || Buffer.byteLength(input) > 2048) return null;
  // domainToASCII first uses the full URL parser.
  // Reject raw host delimiters separately so its path truncation/tab removal cannot become host behavior.
  if (input.startsWith('[')) {
    if (!input.endsWith(']') || /[\x00-\x20\x7f/#?@\\]/u.test(input)) return null;
  } else if (/[\x00-\x20\x7f#/:?@[\\\]^|]/u.test(input)) return null;
  const output = domainToASCII(input);
  return output && Buffer.byteLength(output) <= 2048 ? output : null;
};
const hosts = [...hostInputs].map((input, index) => ({ index, input, output: reference(input) }));
const ordinaryHosts = [...ordinary].map((input, index) => ({ index, input, output: reference(input) }));
const nfc = [];
for (const line of loaded.nfc.split('\n')) {
  const value = line.split('#', 1)[0].trim();
  if (!value || value.startsWith('@')) continue;
  const fields = value.split(';').slice(0, 5).map(s => s.trim().split(/\s+/u).map(c => parseInt(c, 16)));
  assert(fields.every(codes => codes.length <= 128 && codes.every(c => c >= 0 && c <= 0x10ffff)));
  nfc.push({ index: nfc.length, fields });
}
const report = {
  schema: 1, unicode: '16.0.0', node: process.version, node_unicode: process.versions.unicode,
  node_sha256: sha(readFileSync(process.execPath)), url_commit: '8e14777cfa145b08a9fb735fe580ec0c366564c3',
  scope: 'Unicode16 UTS46/NFC normative contracts plus fixed IP/domain controls; Node17 differential rows retained separately.',
  skipped_ill_formed_idna: skippedIllFormed,
  inputs: Object.fromEntries(Object.entries(inputs).map(([name, [, hash]]) => [name, hash])), hosts, ordinaryHosts, idna, nfc,
};
const bytes = JSON.stringify(report) + '\n';
assert(Buffer.byteLength(bytes) < 8_388_608);
if (mode === '--write') writeFileSync(destination, bytes);
else assert.equal(readFileSync(destination, 'utf8'), bytes);
console.log(JSON.stringify({ hosts: hosts.length, ordinary: ordinaryHosts.length, idna: idna.length, nfc: nfc.length, bytes: Buffer.byteLength(bytes), node_unicode: process.versions.unicode }));
