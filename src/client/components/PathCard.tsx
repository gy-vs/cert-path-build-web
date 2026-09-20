import {useState} from 'react';
import {AlertTriangle, CheckCircle2, ChevronDown, ChevronRight, ShieldQuestion, XCircle} from 'lucide-react';
import type {CertView, EdgeCheck, PathResult} from '../types';
import {EdgeEvidence} from './EdgeEvidence';

const STATUS_LABEL: Record<PathResult['status'], string> = {
  trusted: '验证成功',
  invalid: '完整但校验失败',
  incomplete: '路径不完整',
};

const TERMINAL_LABEL: Record<PathResult['terminal'], string> = {
  anchor: '到达信任锚',
  'self-signed-untrusted': '终止于不受信的自签名证书',
  'dead-end': '找不到签发者（缺中间证书/密钥不匹配）',
  'cycle-cut': '检测到环，已剪枝',
};

const AKI_LABEL: Record<EdgeCheck['akiSki'], string> = {
  match: 'AKI ↔ SKI 匹配',
  'subject-no-aki': '子证书无 AKI（仅按名称/签名匹配）',
  'issuer-no-ski': '签发者无 SKI（仅按名称/签名匹配）',
  neither: '双方均无 AKI/SKI 扩展',
  mismatch: 'AKI 与 SKI 不一致',
};

export function PathCard({
  path,
  viewFor,
  dimmed,
}: {
  path: PathResult;
  viewFor: (fp: string) => CertView | null;
  dimmed: boolean;
}) {
  const [open, setOpen] = useState(path.rank === 1);
  const statusClass = `path-status ${path.status}`;

  return (
    <article className={`path-card ${path.status} ${dimmed ? 'dimmed' : ''}`}>
      <header className="path-head" onClick={() => setOpen(o => !o)}>
        <button className="icon-btn">{open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button>
        <span className={`rank rank-${path.rank === 1 ? 'best' : 'other'}`}>#{path.rank}</span>
        <span className={statusClass}>
          {path.status === 'trusted' ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
          {STATUS_LABEL[path.status]}
        </span>
        <span className="muted small">{TERMINAL_LABEL[path.terminal]}</span>
        <span className="spacer" />
        <span className="score">score {path.score}</span>
      </header>

      {open && (
        <div className="path-body">
          <ol className="chain">
            {path.chain.map((fp, i) => {
              const view = viewFor(fp);
              const failures = path.certFailures[fp] ?? [];
              const edge = i < path.edges.length ? path.edges[i] : null;
              return (
                <li key={fp} className="chain-node-wrap">
                  <div className={`chain-node ${failures.length ? 'has-fail' : ''}`}>
                    <div className="node-title">
                      <strong>{view?.cn ?? fp.slice(0, 16)}</strong>
                      {view?.trusted && <span className="tag tag-anchor">信任锚</span>}
                      {view?.selfSigned && <span className="tag">自签名</span>}
                      {view?.isCa && <span className="tag">CA</span>}
                      {i === 0 && <span className="tag tag-leaf">目标</span>}
                    </div>
                    <div className="node-meta muted small">
                      {view?.subject}
                      {' · '}
                      {view?.sigAlg} · 公钥 {view?.subjectKeyType.toUpperCase()} {view?.publicKeyBits}
                      {' · 有效期 '}
                      {view ? `${view.notBefore.slice(0, 10)} ~ ${view.notAfter.slice(0, 10)}` : '?'}
                      {view?.ski && <span className="mono"> · SKI {view.ski.slice(0, 12)}…</span>}
                    </div>
                    {failures.map(f => (
                      <div className="constraint fail" key={f.code}>
                        <XCircle size={13} /> <code>{f.code}</code> — {f.message}
                      </div>
                    ))}
                  </div>
                  {edge && <EdgeEvidence edge={edge} />}
                  {!edge && i < path.chain.length - 1 && (
                    <div className="edge missing">
                      <ShieldQuestion size={15} /> 缺少到上级证书的已验证边
                    </div>
                  )}
                  {i === 0 && path.chain.length === 1 && path.edges[0] && (
                    <EdgeEvidence edge={path.edges[0]} />
                  )}
                </li>
              );
            })}
          </ol>

          {/* rejected candidates attached to any node on this path */}
          {Object.keys(path.rejectedEdges).length > 0 && (
            <div className="rejected">
              <h4>同名但被拒绝的候选签发者</h4>
              {Object.entries(path.rejectedEdges).map(([childFp, edges]) => {
                const child = viewFor(childFp);
                return edges.map(edge => (
                  <div className="constraint warn" key={childFp + edge.issuerFp}>
                    <AlertTriangle size={13} />
                    <span>
                      <strong>{child?.cn ?? childFp.slice(0, 10)}</strong> 的 issuer 名称与{' '}
                      <strong>{viewFor(edge.issuerFp)?.cn ?? edge.issuerFp.slice(0, 10)}</strong>{' '}
                      {edge.nameMatch ? '一致' : '不一致'}，{AKI_LABEL[edge.akiSki]}，签名验证{' '}
                      {edge.signatureVerified === true ? '通过' : '失败'}：
                      <ul>
                        {edge.reasons.map((reason, idx) => (
                          <li key={idx}>{reason}</li>
                        ))}
                      </ul>
                    </span>
                  </div>
                ));
              })}
            </div>
          )}

          <details className="score-details">
            <summary>排序打分依据</summary>
            <table>
              <tbody>
                {path.scoreBreakdown.map(part => (
                  <tr key={part.factor}>
                    <td>{part.factor}</td>
                    <td className="mono">+{part.points}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </div>
      )}
    </article>
  );
}
