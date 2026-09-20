import {describe, expect, it} from 'vitest';
import request from 'supertest';
import {createApp} from '../src/server/api';

describe('path workbench API', () => {
  it('serves generated offline fixtures', async () => {
    const app = createApp();
    const res = await request(app).get('/api/fixtures').expect(200);
    expect(res.body.certsPem).toContain('BEGIN CERTIFICATE');
    expect(res.body.files.find((f: {name: string}) => f.name === 'root-a.pem')).toBeTruthy();
    expect(res.body.files.length).toBeGreaterThan(8);
  });

  it('validates a complete chain and an incomplete chain from posted PEM', async () => {
    const app = createApp();
    const fixtures = await request(app).get('/api/fixtures').expect(200);
    const byName = (name: string) => fixtures.body.files.find((f: {name: string}) => f.name === name).pem;

    const res = await request(app)
      .post('/api/validate')
      .send({
        certPems: [
          [
            byName('leaf.pem'),
            byName('intermediate-a1.pem'),
            byName('root-a-cross-signed-by-b.pem'),
            byName('leaf-copy-duplicate.pem'),
            byName('leaf-expired.pem'),
            byName('leaf-sha1.pem'),
            byName('leaf-missing-intermediate.pem'),
            byName('leaf-untrusted.pem'),
            byName('root-a-same-name-different-key.pem'),
            byName('root-c-untrusted.pem'),
          ].join('\n'),
        ],
        anchorPems: [[byName('root-a.pem'), byName('root-b.pem')].join('\n')],
        verificationTime: '2026-09-01T12:00:00Z',
        policy: {minRsaBits: 2048, allowSha1: false},
        policyRevision: 2,
      })
      .expect(200);

    expect(res.body.policyRevision).toBe(2);
    expect(res.body.verificationTime).toBe('2026-09-01T12:00:00.000Z');

    const leafFp = res.body.certs.find((c: {cn: string}) => c.cn === 'leaf.example').fingerprint;
    const leafPaths = res.body.paths.filter((p: {targetFp: string}) => p.targetFp === leafFp);
    expect(leafPaths[0].status).toBe('trusted');
    expect(leafPaths.some((p: {terminal: string}) => p.terminal === 'anchor')).toBe(true);

    const missingFp = res.body.certs.find((c: {cn: string}) => c.cn === 'leaf-missing.example').fingerprint;
    const missingPaths = res.body.paths.filter((p: {targetFp: string}) => p.targetFp === missingFp);
    expect(missingPaths[0].status).toBe('incomplete');

    // duplicates merged with sources preserved
    expect(res.body.duplicateGroups.length).toBeGreaterThanOrEqual(1);
  });

  it('rejects empty input and bad dates', async () => {
    const app = createApp();
    await request(app).post('/api/validate').send({}).expect(400);
    await request(app)
      .post('/api/validate')
      .send({certPems: ['x'], anchorPems: [], verificationTime: 'not-a-date'})
      .expect(400);
  });

  it('parses pasted PEM bundles', async () => {
    const app = createApp();
    const fixtures = await request(app).get('/api/fixtures').expect(200);
    const res = await request(app)
      .post('/api/parse')
      .send({pem: [fixtures.body.files[0].pem, fixtures.body.files[1].pem].join('\n')})
      .expect(200);
    expect(res.body.items).toHaveLength(2);
    expect(res.body.errors).toHaveLength(0);
  });
});
