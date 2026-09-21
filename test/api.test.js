import {test, describe, before, after} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createServer} from '../src/server/index.js';

let server, base;
before(async () => {
  server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const jget = async (p) => (await fetch(base + p)).json();
const jpost = async (p, body) => {
  const res = await fetch(base + p, {
    method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body),
  });
  return {status: res.status, body: await res.json()};
};

describe('HTTP API', () => {
  test('health reports offline mode', async () => {
    const h = await jget('/api/health');
    assert.equal(h.ok, true);
    assert.equal(h.offline, true);
  });

  test('policies expose revisions', async () => {
    const p = await jget('/api/policies');
    assert.ok(p.policies.length === 3);
    assert.deepEqual(p.policies.map((x) => x.revision), [2, 5, 8]);
    assert.equal(p.defaultPolicyId, 'standard');
  });

  test('fixtures bundle has all required scenarios', async () => {
    const f = await jget('/api/fixtures');
    const ids = f.scenarios.map((s) => s.id);
    for (const id of ['cross', 'gap', 'dup', 'twin', 'expired', 'untrusted', 'legacy', 'pathlen', 'loop']) {
      assert.ok(ids.includes(id), `missing scenario ${id}`);
    }
  });

  test('static index is served', async () => {
    const res = await fetch(base + '/');
    assert.equal(res.status, 200);
    const text = await res.text();
    assert.match(text, /证书链路径工作台/);
  });

  test('build cross scenario: two paths, valid one first, per-edge evidence present', async () => {
    const fx = await jget('/api/fixtures');
    const sc = fx.scenarios.find((s) => s.id === 'cross');
    const map = new Map(fx.certificates.map((c) => [c.label, c]));
    const {status, body} = await jpost('/api/build', {
      certs: sc.certs.map((l) => map.get(l).pem),
      anchors: sc.anchors.map((l) => map.get(l).pem),
      target: map.get(sc.target).fingerprint,
      policyId: 'standard',
      verifyAt: fx.verifyAt,
    });
    assert.equal(status, 200);
    assert.equal(body.paths.length, 2);
    assert.equal(body.paths[0].valid, true);
    assert.equal(body.binding.policyRevision, 5);
    for (const edge of body.paths[0].edges) {
      const checks = edge.evidence.map((e) => e.check);
      assert.ok(checks.includes('name'));
      assert.ok(checks.includes('aki_ski'));
      assert.ok(checks.includes('signature'));
    }
  });

  test('unknown route 404 and bad build 400', async () => {
    assert.equal((await fetch(base + '/api/nope')).status, 404);
    const r = await jpost('/api/build', {certs: ['garbage']});
    assert.equal(r.status, 400);
  });
});
