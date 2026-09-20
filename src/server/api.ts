/**
 * HTTP API for the certificate path workbench.
 *
 * The service is deliberately stateless: every call receives the full
 * certificate pool and trust-anchor pool as PEM/DER text. Nothing is read
 * from the operating-system trust store, and no outbound connection is made.
 */
import express, {Request, Response} from 'express';
import {generateFixtures} from './crypto/fixtures';
import {parseCertificate, splitPemDer} from './crypto/x509';
import {
  AlgorithmPolicy,
  DEFAULT_POLICY,
  PoolEntry,
  validatePaths,
  ValidationReport,
} from './crypto/pathbuilder';

export type ParseError = {index: number; message: string};

export type ParsedItem = {
  fingerprint: string;
  view: {
    subject: string;
    issuer: string;
    cn: string;
    serial: string;
    notBefore: string;
    notAfter: string;
    ski: string | null;
    aki: string | null;
    isCa: boolean;
    selfSigned: boolean;
    sigAlg: string;
    publicKeyBits: number;
  };
  pem: string;
};

function parseBlob(blob: unknown): {items: ParsedItem[]; errors: ParseError[]} {
  const text = typeof blob === 'string' ? blob : '';
  const items: ParsedItem[] = [];
  const errors: ParseError[] = [];
  const blocks = splitPemDer(text);
  if (blocks.length === 0 && text.trim() !== '') {
    errors.push({index: 0, message: 'no PEM CERTIFICATE blocks or parseable DER found'});
    return {items, errors};
  }
  blocks.forEach((der, index) => {
    try {
      const cert = parseCertificate(der);
      items.push({
        fingerprint: cert.fingerprint,
        view: {
          subject: cert.subjectText,
          issuer: cert.issuerText,
          cn: cert.commonName,
          serial: cert.serial,
          notBefore: cert.notBefore.toISOString(),
          notAfter: cert.notAfter.toISOString(),
          ski: cert.ski,
          aki: cert.aki,
          isCa: cert.isCa,
          selfSigned: cert.selfSigned,
          sigAlg: cert.signature.label,
          publicKeyBits: cert.publicKeyBits,
        },
        pem: cert.pem,
      });
    } catch (err) {
      errors.push({index, message: err instanceof Error ? err.message : 'failed to parse certificate'});
    }
  });
  return {items, errors};
}

/** Build the deduped pools used by the path builder. */
function buildPools(certBlobs: string[], anchorBlobs: string[], sourcePrefix: string) {
  const pool = new Map<string, PoolEntry>();
  const anchors = new Map<string, PoolEntry>();

  const ingest = (blob: string, target: Map<string, PoolEntry>, kind: 'cert' | 'anchor', fileIndex: number) => {
    const blocks = splitPemDer(blob);
    blocks.forEach((der, blockIndex) => {
      const cert = parseCertificate(der);
      const source = `${sourcePrefix} ${kind} #${fileIndex + 1}/${blockIndex + 1}`;
      const existing = target.get(cert.fingerprint);
      if (existing) existing.sources.add(source);
      else target.set(cert.fingerprint, {cert, sources: new Set([source]), trusted: kind === 'anchor'});
    });
  };

  certBlobs.forEach((blob, i) => ingest(blob, pool, 'cert', i));
  anchorBlobs.forEach((blob, i) => ingest(blob, anchors, 'anchor', i));

  // When the same certificate is supplied as both cert and anchor, the anchor
  // copy wins for trust but its pool source is preserved for duplicate display.
  for (const [fp, anchorEntry] of anchors) {
    const poolEntry = pool.get(fp);
    if (poolEntry) {
      poolEntry.sources.forEach(s => anchorEntry.sources.add(s));
      pool.delete(fp);
    }
  }
  return {pool, anchors};
}

function readPolicy(body: Request['body']): AlgorithmPolicy {
  const supplied = body?.policy ?? {};
  return {
    minRsaBits: Number.isFinite(Number(supplied.minRsaBits)) ? Number(supplied.minRsaBits) : DEFAULT_POLICY.minRsaBits,
    allowSha1: supplied.allowSha1 === true,
  };
}

export function createApp() {
  const app = express();
  app.use(express.json({limit: '8mb'}));

  app.get('/api/health', (_req, res) => res.json({ok: true, offline: true}));

  // Built-in in-memory fixtures covering every lab scenario.
  app.get('/api/fixtures', (_req: Request, res: Response) => {
    const bundle = generateFixtures();
    res.json({
      certsPem: bundle.certsPem,
      anchorsPem: bundle.anchorsPem,
      files: bundle.files.map(file => ({name: file.name, pem: file.pem, suggestedTrust: file.trust})),
    });
  });

  app.post('/api/parse', (req, res) => {
    const result = parseBlob(req.body?.pem);
    res.json(result);
  });

  app.post('/api/validate', (req, res) => {
    try {
      const certPems: string[] = Array.isArray(req.body?.certPems)
        ? req.body.certPems.filter((x: unknown) => typeof x === 'string')
        : [];
      const anchorPems: string[] = Array.isArray(req.body?.anchorPems)
        ? req.body.anchorPems.filter((x: unknown) => typeof x === 'string')
        : [];

      if (certPems.length === 0 && anchorPems.length === 0) {
        return res.status(400).json({error: 'empty_input', message: 'provide at least one certificate'});
      }

      let verificationTime: Date;
      if (typeof req.body?.verificationTime === 'string') {
        const parsed = new Date(req.body.verificationTime);
        if (Number.isNaN(parsed.getTime())) {
          return res.status(400).json({error: 'bad_time', message: 'verificationTime is not a valid ISO date'});
        }
        verificationTime = parsed;
      } else {
        verificationTime = new Date('2026-09-01T12:00:00Z');
      }

      const {pool, anchors} = buildPools(certPems, anchorPems, 'upload');
      const target = typeof req.body?.target === 'string' ? req.body.target : undefined;
      const policy = readPolicy(req.body);
      const policyRevision = Number.isFinite(Number(req.body?.policyRevision))
        ? Number(req.body.policyRevision)
        : 1;

      const report: ValidationReport = validatePaths({
        pool,
        anchors,
        verificationTime,
        policy,
        policyRevision,
        target,
      });
      return res.json(report);
    } catch (err) {
      return res.status(400).json({
        error: 'validation_failed',
        message: err instanceof Error ? err.message : 'unknown error',
      });
    }
  });

  return app;
}
