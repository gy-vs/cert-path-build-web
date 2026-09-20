import {CheckCircle2, XCircle} from 'lucide-react';
import type {EdgeCheck} from '../types';

const AKI_LABEL: Record<EdgeCheck['akiSki'], string> = {
  match: 'AKI ↔ SKI 匹配',
  'subject-no-aki': '子证书无 AKI（按名称+签名）',
  'issuer-no-ski': '签发者无 SKI（按名称+签名）',
  neither: '双方均无 AKI/SKI',
  mismatch: 'AKI 与 SKI 不一致',
};

/** Per-edge evidence: name matching, AKI/SKI linkage and signature verification. */
export function EdgeEvidence({edge}: {edge: EdgeCheck}) {
  const akiOk = edge.akiSki !== 'mismatch';
  return (
    <div className={`edge ${edge.usable ? 'usable' : 'broken'}`}>
      <span className={`edge-check ${edge.nameMatch ? 'ok' : 'bad'}`}>
        {edge.nameMatch ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
        issuer DN = subject DN
      </span>
      <span className={`edge-check ${akiOk ? 'ok' : 'bad'}`}>
        {akiOk ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
        {AKI_LABEL[edge.akiSki]}
      </span>
      <span className={`edge-check ${edge.signatureVerified ? 'ok' : 'bad'}`}>
        {edge.signatureVerified ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
        签名加密验证{' '}
        {edge.signatureVerified === true ? '通过' : edge.signatureVerified === null ? '未执行' : '失败'}
      </span>
      {edge.reasons.length > 0 && (
        <ul className="edge-reasons">
          {edge.reasons.map((reason, i) => (
            <li key={i}>{reason}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
