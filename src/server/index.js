// Zero-dependency HTTP server. The trust store is always explicit per request;
// neither the OS root store nor any network CRL/OCSP endpoint is consulted.

import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import crypto from 'node:crypto';

import {decodePem} from '../shared/x509.js';
import {buildFixtures} from './fixtures.js';
import {POLICIES, DEFAULT_POLICY_ID, getPolicy, policySummary} from './policy.js';
import {
  importCertificates, buildPaths, rankPaths, certView,
} from './pathBuilder.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_DIR = path.join(__dirname, '..', 'client');
const PORT = Number(process.env.PORT ?? 4174);

let fixturesCache = null;
function fixtures() {
  if (!fixturesCache) fixturesCache = buildFixtures();
  return fixturesCache;
}

function json(res, status, body) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(payload);
}

function readJson(req, limitBytes = 5 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limitBytes) { reject(new Error('payload_too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new Error('invalid_json')); }
    });
    req.on('error', reject);
  });
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/** Decode all PEM/DER payloads (multiline text or base64) into DER buffers. */
function decodeInputs(items) {
  const ders = [];
  for (const item of items ?? []) {
    let payload = typeof item === 'string' ? item : item?.pem ?? item?.der ?? '';
    if (Buffer.isBuffer(payload)) payload = payload;
    else if (typeof payload === 'string' && /[A-Za-z0-9+/=\s-]/.test(payload)) payload = payload;
    for (const der of decodePem(payload)) ders.push(der);
  }
  return ders;
}

/**
 * Core stateless build routine shared by HTTP handler and tests.
 * Input: {certs:[pem|{pem}], anchors:[pem], anchorOrder:[fp], target:fp,
 *         policyId, verifyAt}
 */
export function runBuild(input, fixtureBundle = fixtures()) {
  const certDers = decodeInputs([...(input.certs ?? []), ...(input.anchors ?? []), ...(input.anchorCerts ?? [])]);
  const imported = importCertificates(certDers);
  if (imported.error) return {error: imported.error, detail: imported.detail};

  // Trust anchors arrive as imported certificate material (PEM / raw base64
  // DER), exactly like the workspace certs, plus optional fingerprint refs to
  // workspace certificates that should also be trusted.
  const anchorFps = decodeInputs([...(input.anchors ?? []), ...(input.anchorCerts ?? [])]).map(sha256);
  const parsedByFp = new Map(imported.certs.map((c) => [c.fingerprint256, c]));
  for (const fpRef of input.anchorFingerprints ?? []) {
    if (parsedByFp.has(fpRef)) anchorFps.push(fpRef);
  }

  // Target: fingerprint, or pick the first cert if absent.
  const targetFp = input.target && parsedByFp.has(input.target)
    ? input.target
    : imported.certs[0]?.fingerprint256;
  if (!targetFp) return {error: 'no_certificates'};

  const policy = getPolicy(input.policyId);
  let verifyAt;
  if (input.verifyAt) {
    verifyAt = new Date(input.verifyAt);
    if (Number.isNaN(verifyAt.getTime())) return {error: 'invalid_verify_at'};
  } else {
    verifyAt = new Date(fixtureBundle.verifyAt);
  }

  // Anchor order drives priority: explicit order first, then remaining.
  const knownAnchorFps = [...new Set(anchorFps)].filter((fp) => parsedByFp.has(fp));
  const ordered = [];
  for (const fp of input.anchorOrder ?? []) if (knownAnchorFps.includes(fp) && !ordered.includes(fp)) ordered.push(fp);
  for (const fp of knownAnchorFps) if (!ordered.includes(fp)) ordered.push(fp);

  const result = buildPaths(imported.certs, new Set(ordered), targetFp, policy, verifyAt);
  rankPaths(result, ordered);

  return {
    target: targetFp,
    targetView: certView(parsedByFp.get(targetFp)),
    certificates: imported.certs.map((c) => certView(c, {isAnchor: ordered.includes(c.fingerprint256)})),
    anchors: ordered.map((fp) => certView(parsedByFp.get(fp), {isAnchor: true})),
    duplicates: imported.duplicates,
    paths: result.paths,
    rejectedEdges: result.rejectedEdges,
    binding: {
      policyId: policy.id,
      policyRevision: policy.revision,
      verifyAt: verifyAt.toISOString(),
      computedAt: new Date().toISOString(),
    },
  };
}

async function handleApi(req, res, url) {
  const route = `${req.method} ${url.pathname}`;

  if (route === 'GET /api/health') return json(res, 200, {ok: true, offline: true});

  if (route === 'GET /api/policies') {
    return json(res, 200, {policies: POLICIES.map(policySummary), defaultPolicyId: DEFAULT_POLICY_ID});
  }

  if (route === 'GET /api/fixtures') {
    const fx = fixtures();
    return json(res, 200, {
      verifyAt: fx.verifyAt,
      defaults: fx.defaults,
      certificates: fx.certs.map((c) => ({
        label: c.label,
        role: c.role,
        description: c.description,
        tags: c.tags,
        defaultAnchor: c.defaultAnchor,
        pem: c.der.toString('base64'),
        fingerprint: sha256(c.der),
      })),
      scenarios: fx.scenarios,
    });
  }

  if (route === 'POST /api/parse') {
    const body = await readJson(req);
    const ders = decodeInputs(body.certs);
    const imported = importCertificates(ders);
    if (imported.error) return json(res, 400, imported);
    return json(res, 200, {
      certificates: imported.certs.map((c) => certView(c)),
      duplicates: imported.duplicates,
    });
  }

  if (route === 'POST /api/build') {
    let body;
    try { body = await readJson(req); } catch (e) { return json(res, 400, {error: e.message}); }
    const out = runBuild(body);
    return json(res, out.error ? 400 : 200, out);
  }

  return json(res, 404, {error: 'not_found'});
}

const MIME = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml'};

async function serveStatic(req, res, url) {
  const safePath = url.pathname === '/' ? '/index.html' : url.pathname;
  const filePath = path.normalize(path.join(CLIENT_DIR, safePath));
  if (!filePath.startsWith(CLIENT_DIR)) { res.writeHead(403); return res.end('forbidden'); }
  try {
    const data = await readFile(filePath);
    res.writeHead(200, {'content-type': MIME[path.extname(filePath)] ?? 'application/octet-stream'});
    res.end(data);
  } catch {
    res.writeHead(404, {'content-type': 'text/plain'});
    res.end('not found');
  }
}

export function createServer() {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
      if (req.method === 'GET') return await serveStatic(req, res, url);
      return json(res, 405, {error: 'method_not_allowed'});
    } catch (e) {
      return json(res, 500, {error: 'internal_error', detail: String(e?.message ?? e)});
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  createServer().listen(PORT, '127.0.0.1', () => {
    // Warm the fixture PKI up front so the first request is fast.
    fixtures();
    console.log(`certificate chain workbench: http://127.0.0.1:${PORT} (offline, no OS trust store)`);
  });
}
