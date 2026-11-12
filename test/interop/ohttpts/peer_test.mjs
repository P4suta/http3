// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {Readable} from 'node:stream';
import {KeyConfig, OHTTPClient, OHTTPServer} from 'ohttp-ts';
import {maximumBytes, suite, encodeInner, checkInner, readBounded, encapsulateBounded} from './peer.mjs';

for (const algorithm of [1, 3]) {
  test(`independent AEAD ${algorithm} request, response, trailers and tamper oracle`, async () => {
    const cipher = suite(algorithm);
    const config = await KeyConfig.generate(cipher, 1);
    const client = new OHTTPClient(cipher, config);
    const server = new OHTTPServer([config]);
    const {encapsulatedRequest, context} = await encapsulateBounded(client, encodeInner('request'));
    const opened = await server.decapsulate(encapsulatedRequest);
    checkInner(opened.request, 'request');
    checkInner(await context.decryptResponse(await opened.context.encryptResponse(encodeInner('response'))), 'response');
    const mutated = Buffer.from(encapsulatedRequest); mutated[mutated.length - 1] ^= 1;
    await assert.rejects(server.decapsulate(mutated));
    await assert.rejects(encapsulateBounded(client, Buffer.alloc(maximumBytes + 1)));
  });
}
function authenticatedPlaintextTamperRejected() {
  const bytes = encodeInner('request');
  const at = bytes.indexOf(Buffer.from('ohttp-flow-'));
  assert.equal(at > 0, true);
  bytes[at] ^= 1;
  assert.throws(() => checkInner(bytes, 'request'));
  assert.throws(() => checkInner(encodeInner('response'), 'request'));
  assert.throws(() => checkInner(encodeInner('request').subarray(0, -1), 'request'));
}

test(
  'validly authenticated but changed plaintext cannot satisfy the oracle',
  authenticatedPlaintextTamperRejected,
);
test('outer byte ceiling accepts exactly the limit and rejects one more byte', async () => {
  assert.equal((await readBounded(Readable.from([Buffer.alloc(maximumBytes)]))).byteLength, maximumBytes);
  await assert.rejects(readBounded(Readable.from([Buffer.alloc(maximumBytes), Buffer.alloc(1)])));
});
