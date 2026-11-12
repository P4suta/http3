// SPDX-FileCopyrightText: 2026 the http contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Independent published TypeScript packages; only fixed phase names are logged.
import {readFile} from 'node:fs/promises';
import https from 'node:https';
import {pathToFileURL} from 'node:url';
import {timingSafeEqual} from 'node:crypto';
import {CipherSuite, KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256,
  AEAD_AES_128_GCM, AEAD_ChaCha20Poly1305} from 'hpke';
import {KeyConfig, OHTTPClient, OHTTPServer} from 'ohttp-ts';
import {BHttpRequestStreamEncoder, BHttpResponseStreamEncoder, BHttpStreamDecoder} from 'bhttp-ts';

export const maximumBytes = 131072;
const expectedBody = Buffer.from('ohttp-flow-'.repeat(6000));
class ContractFailure extends Error {}
function requireContract(condition, phase) {
  if (!condition) throw new ContractFailure(phase);
}
const same = (left, right) => left.byteLength === right.byteLength && timingSafeEqual(left, right);
export async function encapsulateBounded(client, bytes) {
  requireContract(bytes.byteLength <= maximumBytes, 'plaintext_limit');
  return await client.encapsulate(bytes);
}
export function suite(algorithm) {
  requireContract(algorithm === 1 || algorithm === 3, 'algorithm');
  return new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256,
    algorithm === 1 ? AEAD_AES_128_GCM : AEAD_ChaCha20Poly1305);
}
export function encodeInner(kind) {
  const request = kind === 'request';
  requireContract(request || kind === 'response', 'inner_kind');
  const encoder = request ? new BHttpRequestStreamEncoder() : new BHttpResponseStreamEncoder();
  const head = request
    ? encoder.encodePreamble('POST', 'https', 'target.example', '/submit', new Headers({'x-request': 'yes'}))
    : encoder.encodePreamble(201, new Headers({'x-response': 'yes'}));
  const content = encoder.encodeContentChunk(expectedBody);
  const tail = encoder.encodeEnd(new Headers({[request ? 'x-request-finished' : 'x-response-finished']: 'yes'}));
  return Buffer.concat([head, content, tail]);
}
export function checkInner(bytes, kind) {
  requireContract(bytes.byteLength <= maximumBytes, 'inner_limit');
  const decoder = new BHttpStreamDecoder({maxMetadataSize: 8192});
  let preamble = 0, trailers = 0, ended = 0, size = 0;
  const content = [];
  const checkHeaders = (headers, name) => {
    requireContract([...headers].length === 1 && headers.get(name) === 'yes', 'inner_fields');
  };
  function observe(event) {
    switch (event.type) {
      case 'request-preamble':
        requireContract(kind === 'request' && preamble++ === 0 && event.method === 'POST'
          && event.scheme === 'https' && event.authority === 'target.example' && event.path === '/submit', 'inner_request');
        checkHeaders(event.headers, 'x-request'); break;
      case 'response-preamble':
        requireContract(kind === 'response' && preamble++ === 0 && event.status === 201, 'inner_response');
        checkHeaders(event.headers, 'x-response'); break;
      case 'content':
        size += event.data.byteLength;
        requireContract(size <= expectedBody.byteLength, 'inner_body_limit');
        content.push(Buffer.from(event.data)); break;
      case 'trailers':
        requireContract(trailers++ === 0, 'duplicate_trailers');
        checkHeaders(event.headers, kind === 'request' ? 'x-request-finished' : 'x-response-finished'); break;
      case 'end': ended++; break;
      default: throw new ContractFailure('unexpected_inner_event');
    }
  }
  for (let offset = 0; offset < bytes.byteLength; offset += 1021)
    for (const event of decoder.push(bytes.subarray(offset, offset + 1021))) observe(event);
  for (const event of decoder.end()) observe(event);
  requireContract(preamble === 1 && trailers === 1 && ended === 1
    && same(Buffer.concat(content), expectedBody), 'inner_oracle');
}
export async function readBounded(stream) {
  let size = 0;
  const chunks = [];
  for await (const chunk of stream) {
    size += chunk.byteLength;
    requireContract(size <= maximumBytes, 'bounded_read');
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
function transport(ca) {
  return new https.Agent({ca, rejectUnauthorized: true, minVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1'], maxSockets: 1, maxTotalSockets: 1,
    keepAlive: true, maxFreeSockets: 1, timeout: 10000});
}
async function exchange(agent, method, endpoint, media, bytes, marker = false) {
  const url = new URL(endpoint);
  requireContract(url.protocol === 'https:' && url.hostname === 'localhost' && !url.username && !url.password, 'outer_endpoint');
  const headers = {'content-length': bytes.byteLength};
  if (media) headers['content-type'] = media;
  if (marker) Object.assign(headers, {'cookie': 'private-fixture-marker', 'x-client-marker': 'must-not-reach-gateway'});
  return await new Promise((resolve, reject) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    const request = https.request(url, {method, agent, headers, maxHeaderSize: 8192,
      signal: controller.signal}, async response => {
      try {
        const body = await readBounded(response);
        resolve({status: response.statusCode, media: response.headers['content-type'] ?? '', body});
      } catch { reject(new ContractFailure('outer_read')); }
      finally { clearTimeout(timer); response.destroy(); }
    });
    request.on('error', () => { clearTimeout(timer); reject(new ContractFailure('outer_exchange')); });
    request.end(bytes);
  });
}
async function client(options) {
  const agent = transport(await readFile(options.ca));
  try {
    const configured = await exchange(agent, 'GET', `${options.endpoint}/config/${options.algorithm}`, '', Buffer.alloc(0));
    requireContract(configured.status === 200 && configured.media === 'application/ohttp-keys', 'configuration_response');
    const configs = KeyConfig.parseMultiple(configured.body);
    requireContract(configs.length === 1, 'configuration_collection');
    const cipher = suite(options.algorithm);
    const peer = new OHTTPClient(cipher, KeyConfig.select(cipher, configs));
    const {encapsulatedRequest, context} = await encapsulateBounded(peer, encodeInner('request'));
    const endpoint = `${options.endpoint}/relay/${options.algorithm}`;
    const response = await exchange(agent, 'POST', endpoint, 'message/ohttp-req', encapsulatedRequest, true);
    requireContract(response.status === 200 && response.media === 'message/ohttp-res', 'response_envelope');
    checkInner(await context.decryptResponse(response.body), 'response');
    const corrupted = Buffer.from(encapsulatedRequest); corrupted[corrupted.length - 1] ^= 1;
    requireContract((await exchange(agent, 'POST', endpoint, 'message/ohttp-req', corrupted, true)).status === 400, 'tamper_rejected');
    requireContract((await exchange(agent, 'POST', endpoint, 'application/octet-stream', corrupted, true)).status === 415, 'media_rejected');
  } finally { agent.destroy(); }
}
async function server(options) {
  const agent = transport(await readFile(options.ca));
  const config = options.role === 'gateway' ? await KeyConfig.generate(suite(options.algorithm), 1) : null;
  const gateway = config ? new OHTTPServer([config]) : null;
  let posts = 0, active = 0, failed = false;
  const connections = new Set();
  const listener = https.createServer({cert: await readFile(options.certificate), key: await readFile(options.key),
    minVersion: 'TLSv1.3', ALPNProtocols: ['http/1.1'], maxHeaderSize: 8192,
    requestTimeout: 10000, headersTimeout: 5000, keepAliveTimeout: 1000}, (request, response) => {
    if (active >= 2) {
      failed = true; request.destroy(); response.destroy(); listener.close(); return;
    }
    active++;
    void (async () => {
      if (request.method === 'GET' && request.url === '/config' && config) {
        response.writeHead(200, {'content-type': 'application/ohttp-keys'});
        response.end(KeyConfig.serializeMultiple([config])); return;
      }
      requireContract(request.method === 'POST' && request.url === '/gateway' && posts < 3, 'server_request');
      const index = posts++;
      const wire = await readBounded(request);
      let status = 415, media = '', body = Buffer.alloc(0);
      if (request.headers['content-type'] === 'message/ohttp-req') {
        if (gateway) {
          let opened;
          try { opened = await gateway.decapsulate(wire); } catch { status = 400; }
          if (opened) {
            checkInner(opened.request, 'request');
            body = await opened.context.encryptResponse(encodeInner('response'));
            status = 200; media = 'message/ohttp-res';
          }
        } else {
          // Only the ciphertext and media type reach the fixed gateway.
          ({status, media, body} = await exchange(agent, 'POST', `${options.endpoint}/gateway/${options.algorithm}`, 'message/ohttp-req', wire));
        }
      }
      requireContract(status === [200, 400, 415][index], 'server_oracle');
      response.writeHead(status, media ? {'content-type': media} : {});
      response.end(body);
      if (posts === 3) listener.close();
    })().catch(() => { failed = true; response.destroy(); listener.close(); })
      .finally(() => { active--; });
  });
  listener.maxConnections = 2;
  listener.maxHeadersCount = 32;
  listener.maxRequestsPerSocket = 4;
  listener.setTimeout(10000, socket => socket.destroy());
  listener.on('connection', socket => {
    connections.add(socket); socket.on('close', () => connections.delete(socket));
  });
  const absolute = setTimeout(() => {
    failed = true; listener.close(); for (const socket of connections) socket.destroy();
  }, 45000);
  try {
    await new Promise((resolve, reject) => {
      listener.once('error', () => reject(new ContractFailure('server_listen')));
      listener.listen(0, '127.0.0.1', resolve);
    });
    process.stdout.write(`PORT=${listener.address().port}\n`);
    await new Promise(resolve => listener.once('close', resolve));
    // Server.close can precede the individual socket's close event and the request callback's final microtask.
    // Observe both before reporting success.
    const joinedBy = performance.now() + 5000;
    while (active !== 0 || connections.size !== 0) {
      requireContract(performance.now() < joinedBy, 'server_cleanup_deadline');
      await new Promise(resolve => setTimeout(resolve, 5));
    }
    requireContract(!failed && posts === 3 && active === 0 && connections.size === 0, 'server_completion');
  } finally {
    clearTimeout(absolute); agent.destroy(); listener.close();
    for (const socket of connections) socket.destroy();
  }
}
function options(arguments_) {
  requireContract(arguments_.length > 0 && arguments_.length <= 12 && arguments_.length % 2 === 0, 'arguments');
  const result = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index].slice(2);
    requireContract(arguments_[index].startsWith('--') && ['role', 'algorithm', 'endpoint', 'ca', 'certificate', 'key'].includes(name)
      && !Object.hasOwn(result, name), 'arguments');
    result[name] = arguments_[index + 1];
  }
  requireContract(['client', 'relay', 'gateway'].includes(result.role) && ['1', '3'].includes(result.algorithm), 'role');
  result.algorithm = Number(result.algorithm);
  return result;
}
async function main() {
  const configuration = options(process.argv.slice(2));
  await (configuration.role === 'client' ? client(configuration) : server(configuration));
  process.stdout.write('OHTTP TypeScript contract verified\n');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    process.stderr.write(`OHTTP TypeScript failed: ${error instanceof ContractFailure ? error.message : 'unexpected_failure'}\n`);
    process.exitCode = 1;
  });
}
