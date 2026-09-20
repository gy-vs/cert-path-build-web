import {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {
  AlertTriangle,
  FileUp,
  FlaskConical,
  Link2,
  Play,
  Shield,
  ShieldOff,
  Trash2,
  XCircle,
} from 'lucide-react';
import {api} from './api';
import type {CertView, ValidationReport} from './types';
import {PathCard} from './components/PathCard';

type CertEntry = {
  id: string;
  name: string;
  pem: string;
  role: 'cert' | 'anchor';
};

type ReportSnapshot = {
  report: ValidationReport;
  policyRevision: number;
  inputRevision: number;
  time: string;
};

const DEFAULT_TIME = '2026-09-01T12:00:00';
const DEFAULT_POLICY = {minRsaBits: 2048, allowSha1: false};

let idCounter = 0;
const nextId = () => `entry-${++idCounter}`;

function bufferToLatin1(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let out = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    out += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return out;
}

export default function App() {
  const [entries, setEntries] = useState<CertEntry[]>([]);
  const [target, setTarget] = useState<string>('');
  const [time, setTime] = useState(DEFAULT_TIME);
  const [policy, setPolicy] = useState(DEFAULT_POLICY);
  const [policyRevision, setPolicyRevision] = useState(1);
  const [inputRevision, setInputRevision] = useState(0);
  const [snapshot, setSnapshot] = useState<ReportSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);

  const bumpPolicy = useCallback((patch: Partial<typeof policy>) => {
    setPolicy(prev => ({...prev, ...patch}));
    setPolicyRevision(rev => rev + 1);
  }, []);

  const addEntries = useCallback((items: {name: string; pem: string; role: 'cert' | 'anchor'}[]) => {
    setEntries(prev => {
      const existing = new Set(prev.map(e => e.pem));
      const fresh = items.filter(i => !existing.has(i.pem)).map(i => ({...i, id: nextId()}));
      return [...prev, ...fresh];
    });
    setInputRevision(rev => rev + 1);
  }, []);

  const loadFixtures = useCallback(async () => {
    const fixtures = await api.fixtures();
    const loaded = fixtures.files.map(file => ({
      name: file.name,
      pem: file.pem,
      role: file.suggestedTrust === 'anchor' ? 'anchor' as const : 'cert' as const,
    }));
    setEntries(loaded.map(e => ({...e, id: nextId()})));
    setInputRevision(rev => rev + 1);
    setSnapshot(null);
    setTarget('');
  }, []);

  const onFiles = useCallback(
    async (files: FileList | null, role: 'cert' | 'anchor') => {
      if (!files) return;
      const items: {name: string; pem: string; role: 'cert' | 'anchor'}[] = [];
      for (const file of Array.from(files)) {
        // Read as latin1 so binary DER (non-UTF8) round-trips byte-for-byte;
        // PEM is pure ASCII so it is unaffected.
        const buffer = await file.arrayBuffer();
        const isPem = /-----BEGIN CERTIFICATE-----/.test(
          new TextDecoder('ascii').decode(buffer.slice(0, 64))
        );
        const pem = isPem ? new TextDecoder('utf8').decode(buffer) : bufferToLatin1(buffer);
        items.push({name: file.name, pem, role});
      }
      addEntries(items);
    },
    [addEntries]
  );

  const runValidation = useCallback(async () => {
    if (entries.length === 0) {
      setError('请先导入至少一张证书');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const report = await api.validate({
        certPems: entries.filter(e => e.role === 'cert').map(e => e.pem),
        anchorPems: entries.filter(e => e.role === 'anchor').map(e => e.pem),
        verificationTime: new Date(time + 'Z').toISOString(),
        policy,
        policyRevision,
        target: target || undefined,
      });
      setSnapshot({report, policyRevision, inputRevision, time});
      if (!target || !report.targets.includes(target)) {
        const preferred = report.targets.find(fp => report.certs.find(c => c.fingerprint === fp)?.cn === 'leaf.example');
        setTarget(preferred ?? report.targets[0] ?? '');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [entries, time, policy, policyRevision, inputRevision, target]);

  // auto-run once after fixtures are loaded the first time
  const [autoRunDone, setAutoRunDone] = useState(false);
  useEffect(() => {
    if (!autoRunDone && entries.length > 0 && !snapshot && !busy) {
      setAutoRunDone(true);
      runValidation();
    }
  }, [autoRunDone, entries, snapshot, busy, runValidation]);

  const stale = useMemo(() => {
    if (!snapshot) return false;
    return (
      snapshot.policyRevision !== policyRevision ||
      snapshot.inputRevision !== inputRevision ||
      snapshot.time !== time
    );
  }, [snapshot, policyRevision, inputRevision, time]);

  const report = snapshot?.report ?? null;
  const certByFp = useMemo(() => {
    const map = new Map<string, CertView>();
    report?.certs.forEach(c => map.set(c.fingerprint, c));
    report?.anchors.forEach(c => map.set(c.fingerprint, c));
    return map;
  }, [report]);

  const targetPaths = useMemo(() => {
    const paths = report?.paths ?? [];
    if (target) return paths.filter(p => p.targetFp === target);
    return paths;
  }, [report, target]);

  const trustedCount = entries.filter(e => e.role === 'anchor').length;

  return (
    <main className="shell">
      <header className="topbar">
        <FlaskConical size={20} />
        <strong>证书路径工作台</strong>
        <span className="badge">离线 · 仅本地 PEM/DER</span>
        <span className="spacer" />
        <button className="btn" onClick={loadFixtures}>
          <FlaskConical size={14} /> 载入内置场景夹具
        </button>
      </header>

      <section className="layout">
        {/* left: imports */}
        <aside className="pane imports">
          <h2>证书与信任锚</h2>
          <div className="import-row">
            <button className="btn" onClick={() => fileInput.current?.click()}>
              <FileUp size={14} /> 导入证书 (DER/PEM)
            </button>
            <input
              ref={fileInput}
              type="file"
              accept=".pem,.crt,.cer,.der,application/pkix-cert,text/plain"
              multiple
              hidden
              onChange={e => onFiles(e.target.files, 'cert')}
            />
            <button className="btn" onClick={() => setPasteOpen(open => !open)}>
              粘贴 PEM
            </button>
          </div>
          {pasteOpen && (
            <div className="paste-box">
              <textarea
                value={pasteText}
                onChange={e => setPasteText(e.target.value)}
                placeholder="粘贴一张或多张 -----BEGIN CERTIFICATE-----"
                rows={6}
              />
              <div className="import-row">
                <button
                  className="btn primary"
                  onClick={() => {
                    if (pasteText.trim()) addEntries([{name: 'pasted.pem', pem: pasteText, role: 'cert'}]);
                    setPasteText('');
                    setPasteOpen(false);
                  }}
                >
                  加入证书池
                </button>
              </div>
            </div>
          )}

          <div className="entry-list">
            {entries.length === 0 && <p className="muted">尚未导入证书。点击"载入内置场景夹具"快速开始。</p>}
            {entries.map(entry => (
              <CertEntryRow
                key={entry.id}
                entry={entry}
                onToggleRole={() => {
                  setEntries(prev =>
                    prev.map(e => (e.id === entry.id ? {...e, role: e.role === 'anchor' ? 'cert' : 'anchor'} : e))
                  );
                  setInputRevision(rev => rev + 1);
                }}
                onRemove={() => {
                  setEntries(prev => prev.filter(e => e.id !== entry.id));
                  setInputRevision(rev => rev + 1);
                }}
              />
            ))}
          </div>

          {report && report.duplicateGroups.length > 0 && (
            <div className="note">
              <AlertTriangle size={14} /> 检测到 {report.duplicateGroups.length} 组重复证书（相同 DER
              已合并，来源全部保留）。
            </div>
          )}
        </aside>

        {/* center: controls + results */}
        <section className="pane results">
          <div className="controls">
            <label>
              验证逻辑时间
              <input type="datetime-local" step={1} value={time} onChange={e => setTime(e.target.value)} />
            </label>
            <label>
              RSA 最小密钥长度
              <select
                value={policy.minRsaBits}
                onChange={e => bumpPolicy({minRsaBits: Number(e.target.value)})}
              >
                <option value={1024}>1024（宽松）</option>
                <option value={2048}>2048（默认）</option>
                <option value={3072}>3072（严格）</option>
              </select>
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={policy.allowSha1}
                onChange={e => bumpPolicy({allowSha1: e.target.checked})}
              />
              允许 SHA-1
            </label>
            <button className="btn primary" onClick={runValidation} disabled={busy}>
              <Play size={14} /> {busy ? '枚举中…' : stale ? '重新验证' : '构建路径'}
            </button>
            <span className="rev">策略 revision #{policyRevision}</span>
          </div>

          {error && (
            <div className="banner error">
              <XCircle size={15} /> {error}
            </div>
          )}

          {stale && (
            <div className="banner stale">
              <AlertTriangle size={15} /> 当前结果基于旧的策略 revision #{snapshot?.policyRevision}
              {snapshot && snapshot.time !== time && ` / 时间 ${snapshot.time}`}（输入版本
              #{snapshot?.inputRevision}），已标记为过期——点击"重新验证"。
            </div>
          )}

          {report && (
            <>
              <div className="target-bar">
                <label>
                  验证目标
                  <select value={target} onChange={e => setTarget(e.target.value)}>
                    {report.targets.map(fp => {
                      const view = certByFp.get(fp);
                      return (
                        <option key={fp} value={fp}>
                          {view?.cn ?? fp.slice(0, 12)} {view?.trusted ? '（锚）' : ''}
                        </option>
                      );
                    })}
                  </select>
                </label>
                <span className="muted small">
                  <Link2 size={13} /> 共枚举 {report.paths.length} 条路径
                  {report.truncated && `（达到上限 ${report.enumeratedCap}，已截断）`}；逻辑时间{' '}
                  {report.verificationTime}
                </span>
              </div>

              <div className="paths">
                {targetPaths.length === 0 && <p className="muted">该目标没有可显示的路径。</p>}
                {targetPaths.map(path => (
                  <PathCard
                    key={path.id}
                    path={path}
                    viewFor={fp => certByFp.get(fp) ?? null}
                    dimmed={stale}
                  />
                ))}
              </div>
            </>
          )}
          {!report && !error && <p className="muted hint">导入证书后点击"构建路径"。</p>}
        </section>
      </section>

      <footer className="statusbar">
        <span>
          证书 {entries.filter(e => e.role === 'cert').length} 张 · 信任锚 {trustedCount} 个
        </span>
        <span className="spacer" />
        <span>不访问系统证书库，不发起任何网络请求</span>
      </footer>
    </main>
  );
}

function CertEntryRow({
  entry,
  onToggleRole,
  onRemove,
}: {
  entry: CertEntry;
  onToggleRole: () => void;
  onRemove: () => void;
}) {
  const isAnchor = entry.role === 'anchor';
  return (
    <div className={`entry ${isAnchor ? 'anchor' : ''}`}>
      <button className="icon-btn" title={isAnchor ? '移到证书池' : '提升为信任锚'} onClick={onToggleRole}>
        {isAnchor ? <Shield size={15} className="ok" /> : <ShieldOff size={15} />}
      </button>
      <span className="entry-name" title={entry.name}>
        {entry.name}
      </span>
      <span className={`tag ${isAnchor ? 'tag-anchor' : ''}`}>{isAnchor ? '信任锚' : '候选证书'}</span>
      <button className="icon-btn" title="删除" onClick={onRemove}>
        <Trash2 size={14} />
      </button>
    </div>
  );
}
