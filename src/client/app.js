// Certificate chain workbench — vanilla JS UI.
// All data is local; the only network calls are same-origin /api/* requests
// served by the offline Node server.

const $ = (id) => document.getElementById(id);

const state = {
  fixtures: null,
  policies: [],
  defaultPolicyId: 'standard',
  // workspace items: [{ fp, derBase64, label, source, view? }]
  certs: [],
  // ordered anchor fingerprints
  anchorFps: [],
  // extra anchor-only imports also live in `certs` but flagged source='anchor'
  targetFp: null,
  policyId: 'standard',
  verifyAt: null, // Date
  scenarioId: null,
  result: null,
  resultToken: null, // binding signature of the inputs that produced result
  parseTimer: null,
};

// ---------- helpers ----------
const b64ToBytes = (b64) => Uint8Array.from(atob(b64.replace(/\s+/g, '')), (c) => c.charCodeAt(0));
const bytesToB64 = (bytes) => btoa(String.fromCharCode(...bytes));

// Split a PEM / raw-base64 text into base64-DER strings.
function splitPem(text) {
  const out = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m;
  while ((m = re.exec(text))) out.push(m[1].replace(/\s+/g, ''));
  if (!out.length) {
    const compact = text.replace(/\s+/g, '');
    if (compact && /^[A-Za-z0-9+/=]+$/.test(compact)) out.push(compact);
  }
  return out;
}

async function fpOfBase64(derB64) {
  const digest = await crypto.subtle.digest('SHA-256', b64ToBytes(derB64));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function api(path, body) {
  const res = await fetch(path, body ? {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify(body),
  } : undefined);
  const j = await res.json();
  if (!res.ok) throw Object.assign(new Error(j.error || 'request failed'), {body: j});
  return j;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
}
const cn = (dn) => {
  const m = /(?:^|,\s*)CN=([^,]*)/.exec(dn ?? '');
  return m ? m[1] : (dn ?? '');
};
const shortFp = (fp) => fp ? fp.slice(0, 8) + '…' + fp.slice(-6) : '';
const shortId = (hex) => hex ? hex.slice(0, 10) + '…' : '—';

function pad2(n) { return String(n).padStart(2, '0'); }
function toLocalInput(d) {
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
}
function fromLocalInput(v) { return new Date(v + 'Z'); }

// Token = hash of all build-affecting inputs; mismatch => stale results.
async function currentToken() {
  const material = JSON.stringify({
    certs: state.certs.map((c) => c.derBase64),
    anchors: state.anchorFps,
    target: state.targetFp,
    policy: state.policyId,
    at: state.verifyAt?.toISOString() ?? null,
  });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
  return bytesToB64(new Uint8Array(digest));
}

// ---------- import handling ----------
async function addBase64Ders(list, source) {
  let added = 0;
  for (const derB64 of list) {
    const fp = await fpOfBase64(derB64);
    if (state.certs.some((c) => c.fp === fp)) continue; // de-dupe identical DER
    state.certs.push({fp, derB64, source, label: shortFp(fp)});
    added++;
  }
  return added;
}

async function readFiles(fileList) {
  const collected = [];
  for (const f of fileList) {
    const buf = new Uint8Array(await f.arrayBuffer());
    // Binary DER starts with SEQUENCE tag 0x30 and is not valid UTF-8 text.
    if (buf[0] === 0x30 && !looksLikeText(buf)) {
      collected.push(bytesToB64(buf));
      continue;
    }
    const asText = new TextDecoder().decode(buf);
    if (asText.includes('-----BEGIN')) {
      collected.push(...splitPem(asText));
    } else {
      const compact = asText.replace(/\s+/g, '');
      if (/^[A-Za-z0-9+/=]+$/.test(compact) && compact.length > 0) {
        collected.push(...splitPem(compact));
      }
    }
  }
  return collected;
}

function looksLikeText(buf) {
  // Heuristic: no NUL bytes and most bytes are printable / whitespace / CR/LF.
  let printable = 0;
  const sample = buf.subarray(0, Math.min(buf.length, 512));
  for (const b of sample) {
    if (b === 0) return false;
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) printable++;
  }
  return printable / sample.length > 0.95;
}

// ---------- rendering: left column ----------
function renderScenarios() {
  const el = $('scenario-list');
  el.innerHTML = state.fixtures.scenarios.map((s) => `
    <button class="scenario ${state.scenarioId === s.id ? 'active' : ''}" data-scenario="${esc(s.id)}">
      <span class="sc-title">${esc(s.title)}</span>
      <span class="sc-desc">${esc(s.description)}</span>
      <span class="sc-meta">${s.certs.length} 张证书 · ${s.anchors.length} 个锚</span>
    </button>`).join('');
}

function renderInventory(viewsByFp) {
  const el = $('cert-inventory');
  if (!state.certs.length) { el.innerHTML = '<span class="muted">尚未导入证书</span>'; return; }
  el.innerHTML = state.certs.map((c) => {
    const v = viewsByFp?.get(c.fp);
    const isAnchor = state.anchorFps.includes(c.fp);
    const expired = v && new Date(v.notAfter) < state.verifyAt;
    return `<div class="inv-row ${isAnchor ? 'is-anchor' : ''}" data-fp="${esc(c.fp)}">
      <label class="inv-anchor" title="标记为信任锚">
        <input type="checkbox" data-action="toggle-anchor" ${isAnchor ? 'checked' : ''}>
      </label>
      <div class="inv-main">
        <div class="inv-name" title="${esc(v?.subject ?? c.label)}">
          ${v ? esc(cn(v.subject)) : esc(c.label)}
          ${v?.isCa ? '<span class="tag ca">CA</span>' : ''}
          ${v?.selfIssued ? '<span class="tag self">自签名</span>' : ''}
          ${expired ? '<span class="tag exp">已过期</span>' : ''}
          ${c.source === 'anchor-file' ? '<span class="tag anchorf">锚文件</span>' : ''}
        </div>
        <div class="inv-meta">${v
          ? `${esc(v.key.type.toUpperCase())} ${v.key.strength || ''} · ${esc(v.sigAlg)} · 至 ${v.notAfter.slice(0, 10)}`
          : '解析中…'}</div>
      </div>
      <div class="inv-actions">
        <button data-action="set-target" title="设为目标">◎</button>
        <button data-action="remove" title="移除">✕</button>
      </div>
    </div>`;
  }).join('');
}

function renderAnchors() {
  const el = $('anchor-list');
  if (!state.anchorFps.length) { el.innerHTML = '<li class="muted">尚无信任锚</li>'; return; }
  el.innerHTML = state.anchorFps.map((fp, i) => {
    const c = state.certs.find((x) => x.fp === fp);
    return `<li class="anchor-row" data-fp="${esc(fp)}">
      <span class="anchor-prio">#${i + 1}</span>
      <span class="anchor-name" title="${esc(c?.view?.subject ?? fp)}">${esc(cn(c?.view?.subject) ?? shortFp(fp))}</span>
      <button data-action="anchor-up" ${i === 0 ? 'disabled' : ''}>↑</button>
      <button data-action="anchor-down" ${i === state.anchorFps.length - 1 ? 'disabled' : ''}>↓</button>
      <button data-action="anchor-remove">✕</button>
    </li>`;
  }).join('');
}

function renderTarget(viewsByFp) {
  const sel = $('target-select');
  const prev = state.targetFp;
  sel.innerHTML = state.certs.map((c) => {
    const v = viewsByFp?.get(c.fp);
    return `<option value="${esc(c.fp)}" ${c.fp === state.targetFp ? 'selected' : ''}>
      ${v ? esc(cn(v.subject)) + (v.selfIssued ? '（自签名）' : '') : esc(c.label)}
    </option>`;
  }).join('');
  if (prev && state.certs.some((c) => c.fp === prev)) sel.value = prev;
}

function renderPolicies() {
  $('policy-list').innerHTML = state.policies.map((p) => `
    <label class="policy ${state.policyId === p.id ? 'active' : ''}">
      <input type="radio" name="policy" value="${esc(p.id)}" ${state.policyId === p.id ? 'checked' : ''}>
      <span class="policy-label">${esc(p.label)}</span>
      <span class="policy-desc">${esc(p.description)}</span>
    </label>`).join('');
}

// ---------- rendering: results ----------
function renderResult() {
  const r = state.result;
  if (!r) {
    $('empty-state').classList.remove('hidden');
    $('paths-panel').classList.add('hidden');
    $('result-summary').classList.add('hidden');
    return;
  }
  $('empty-state').classList.add('hidden');
  $('paths-panel').classList.remove('hidden');
  $('result-summary').classList.remove('hidden');

  const valid = r.paths.filter((p) => p.valid).length;
  const invalid = r.paths.filter((p) => !p.valid && p.terminal === 'anchor').length;
  const untrusted = r.paths.length - valid - invalid;
  $('summary-body').innerHTML = `
    <div class="summary-grid">
      <div class="stat valid"><b>${valid}</b><span>有效路径</span></div>
      <div class="stat bad"><b>${invalid}</b><span>到锚但约束失败</span></div>
      <div class="stat warn"><b>${untrusted}</b><span>无法到锚</span></div>
      <div class="stat"><b>${r.paths.length}</b><span>候选总数（全部保留）</span></div>
    </div>
    <div class="binding ${isStale() ? 'stale' : ''}">
      绑定：策略 <b>${esc(r.binding.policyId)}</b> rev <b>${r.binding.policyRevision}</b>
      · 逻辑时间 <b>${esc(r.binding.verifyAt.replace('T', ' ').replace('.000Z', ' UTC'))}</b>
      · 计算于 ${esc(r.binding.computedAt.slice(11, 19))}
      ${isStale() ? '<span class="stale-tag">已过期</span>' : '<span class="fresh-tag">当前</span>'}
    </div>
    ${r.duplicates?.length ? `<div class="dup-note">检测到 ${r.duplicates.length} 张重复 DER，已去重（不会产生伪路径）。</div>` : ''}
  `;

  $('paths').innerHTML = r.paths.map((p, idx) => pathCard(p, idx)).join('') ||
    '<div class="card">未枚举出任何路径。</div>';
  renderRejected();
}

function pathCard(p, idx) {
  const stale = isStale();
  const cls = p.valid ? 'valid' : p.terminal === 'anchor' ? 'invalid' : 'untrusted';
  const badge = {
    valid: ['✓ 验证成功', 'ok'], invalid: ['✗ 到达锚但失败', 'bad'], untrusted: ['⚠ 不受信', 'warn'],
  }[cls];
  return `<article class="path-card ${cls} ${stale ? 'stale' : ''}">
    <header class="path-head">
      <span class="rank">#${idx + 1}</span>
      <span class="path-badge ${badge[1]}">${badge[0]}</span>
      <span class="path-term">${esc(p.terminalLabel)}</span>
      <span class="path-score">排序分 ${p.score}</span>
      ${p.anchorPriority !== null ? `<span class="path-anchor">锚优先级 #${p.anchorPriority + 1}</span>` : ''}
      ${stale ? '<span class="stale-ribbon">旧结果 · 已过期</span>' : ''}
    </header>
    <div class="chain">
      ${interleaveNodesEdges(p)}
    </div>
    ${p.failureReasons.length ? `<footer class="path-fails"><b>失败约束：</b>${p.failureReasons.map(esc).join('、')}</footer>` : ''}
  </article>`;
}

function interleaveNodesEdges(p) {
  let html = nodeBlock(p.nodes[0], 0, p);
  for (let i = 1; i < p.nodes.length; i++) {
    html += edgeBlock(p.edges[i - 1], i - 1);
    html += nodeBlock(p.nodes[i], i, p);
  }
  return html;
}

function nodeBlock(n, ni, p) {
  const checks = n.checks.map((c) => `
    <li class="${c.ok ? (c.severity === 'warning' ? 'warn' : 'ok') : 'bad'}">
      ${c.ok ? (c.severity === 'warning' ? '⚠' : '✓') : '✗'} ${esc(c.detail)}
    </li>`).join('');
  return `<div class="node ${n.isAnchor ? 'anchor' : ''} ${ni === 0 ? 'target' : ''}">
    <div class="node-head">
      <span class="node-title">${esc(cn(n.subject))}</span>
      ${ni === 0 ? '<span class="tag tgt">目标</span>' : ''}
      ${n.isAnchor ? '<span class="tag anch">信任锚</span>' : ''}
    </div>
    <div class="node-meta">
      ${esc(n.subject.replace(cn(n.subject), '').replace(/^,\s*/, ''))}
      <br>${esc(n.keyInfo.type.toUpperCase())} ${n.keyInfo.strength || ''}
      · ${esc(n.sigAlg)} · 序列号 ${esc(shortId(n.serial))}
      <br>有效期 ${esc(n.notBefore.slice(0, 10))} → ${esc(n.notAfter.slice(0, 10))}
      <br>SKI ${esc(shortId(n.ski))} · AKI ${esc(shortId(n.aki))}
    </div>
    ${checks ? `<ul class="checks">${checks}</ul>` : ''}
  </div>`;
}

function edgeBlock(e, ei) {
  if (!e) return '';
  const ev = e.evidence.map((c) => `
    <li class="${c.ok ? (c.severity === 'warning' || c.severity === 'info' ? 'warn' : 'ok') : 'bad'}">
      ${c.ok ? (c.severity === 'warning' ? '⚠' : c.severity === 'info' ? 'ℹ' : '✓') : '✗'}
      <code>${esc(c.check)}</code> — ${esc(c.detail)}
    </li>`).join('');
  return `<div class="edge ${e.errors.length ? 'has-errors' : ''}" data-edge="${ei}">
    <div class="edge-arrow">↑ 签名连接</div>
    <ul class="evidence">${ev}</ul>
  </div>`;
}

function renderRejected() {
  const r = state.result;
  const el = $('rejected-list');
  if (!r?.rejectedEdges?.length) { el.innerHTML = '<span class="muted">无</span>'; return; }
  const reasonText = {
    signature_invalid: '签名验证失败',
    signature_key_type_mismatch: '签名/密钥类型不匹配',
    signature_algorithm_unsupported: '不支持的签名算法',
    aki_ski_mismatch: 'AKI/SKI 不匹配（同名不同密钥）',
    algorithm_policy_rejected: '算法策略否决',
    cycle: '构成环路（剪枝）',
  };
  el.innerHTML = r.rejectedEdges.map((e) => {
    const evidence = e.evidence?.filter((x) => !x.ok || x.check === 'aki_ski')
      .map((x) => `<li class="${x.ok ? 'warn' : 'bad'}">${x.ok ? '⚠' : '✗'} <code>${esc(x.check)}</code> — ${esc(x.detail)}</li>`).join('');
    return `<div class="rej-row">
      <div class="rej-edge">
        <b>${esc(cn(e.childSubject))}</b>
        <span class="rej-arrow">⇢ ${esc(reasonText[e.reason] ?? e.reason)} ⇢</span>
        <b>${esc(cn(e.parentSubject))}</b>
      </div>
      <div class="rej-detail">${esc(e.detail ?? '')}</div>
      ${evidence ? `<ul class="evidence">${evidence}</ul>` : ''}
    </div>`;
  }).join('');
}

// ---------- stale handling ----------
function isStale() {
  return Boolean(state.result) && state.resultToken !== state._liveToken;
}
function updateStale() {
  $('stale-banner').classList.toggle('hidden', !isStale());
  if (state.result) {
    document.querySelectorAll('.path-card').forEach((el) => el.classList.toggle('stale', isStale()));
    document.querySelector('.binding')?.classList.toggle('stale', isStale());
  }
}
async function touchInputs() {
  state._liveToken = await currentToken();
  updateStale();
}

// ---------- server actions ----------
async function reparsedViews() {
  if (!state.certs.length) return new Map();
  const r = await api('/api/parse', {certs: state.certs.map((c) => c.derBase64)});
  return new Map(r.certificates.map((v) => [v.fingerprint, v]));
}

let reparseQueued = false;
function scheduleReparse() {
  clearTimeout(state.parseTimer);
  state.parseTimer = setTimeout(async () => {
    try {
      const views = await reparsedViews();
      for (const c of state.certs) c.view = views.get(c.fp);
      renderInventory(views);
      renderAnchors();
      renderTarget(views);
    } catch (e) { /* ignore parse hiccups while typing */ }
  }, 200);
}

async function loadScenario(id) {
  const sc = state.fixtures.scenarios.find((s) => s.id === id);
  if (!sc) return;
  state.scenarioId = id;
  state.certs = [];
  state.anchorFps = [];
  const byLabel = new Map(state.fixtures.certificates.map((c) => [c.label, c]));
  for (const label of new Set(sc.certs)) {
    const f = byLabel.get(label);
    if (!state.certs.some((c) => c.fp === f.fingerprint)) {
      state.certs.push({fp: f.fingerprint, derB64: f.pem, source: 'fixture', label, view: undefined});
    }
  }
  for (const label of sc.anchors) {
    const f = byLabel.get(label);
    if (!state.anchorFps.includes(f.fingerprint)) state.anchorFps.push(f.fingerprint);
  }
  state.targetFp = byLabel.get(sc.target)?.fingerprint ?? state.certs[0]?.fp ?? null;
  state.verifyAt = new Date(state.fixtures.verifyAt);
  $('verify-at').value = toLocalInput(state.verifyAt);
  renderScenarios();
  const views = await reparsedViews();
  for (const c of state.certs) c.view = views.get(c.fp);
  renderInventory(views); renderAnchors(); renderTarget(views);
  await touchInputs();
  await doBuild();
}

async function doBuild() {
  if (!state.certs.length) return;
  $('btn-build').disabled = true;
  try {
    const body = {
      certs: state.certs.map((c) => c.derBase64),
      anchorFingerprints: state.anchorFps,
      anchorOrder: state.anchorFps,
      target: state.targetFp,
      policyId: state.policyId,
      verifyAt: state.verifyAt.toISOString(),
    };
    state.result = await api('/api/build', body);
    state.resultToken = await currentToken();
    state._liveToken = state.resultToken;
    // refresh local views from authoritative parse
    for (const c of state.certs) {
      c.view = state.result.certificates.find((x) => x.fingerprint === c.fp) ?? c.view;
    }
    renderResult();
    renderInventory(new Map(state.result.certificates.map((v) => [v.fingerprint, v])));
    updateStale();
  } catch (e) {
    $('summary-body') && ($('result-summary').classList.remove('hidden'));
    $('summary-body').innerHTML = `<div class="error-box">构建失败：${esc(e.body?.detail ?? e.message)}</div>`;
  } finally {
    $('btn-build').disabled = false;
  }
}

// ---------- init + events ----------
async function init() {
  const [fx, pol] = await Promise.all([api('/api/fixtures'), api('/api/policies')]);
  state.fixtures = fx;
  state.policies = pol.policies;
  state.policyId = pol.defaultPolicyId;
  state.verifyAt = new Date(fx.verifyAt);
  $('verify-at').value = toLocalInput(state.verifyAt);
  $('binding-info').textContent = `场景默认校验时间：${fx.verifyAt.replace('T', ' ').replace('.000Z', ' UTC')}`;

  renderScenarios(); renderPolicies(); renderInventory(); renderAnchors(); renderTarget();

  $('scenario-list').addEventListener('click', (e) => {
    const b = e.target.closest('[data-scenario]');
    if (b) loadScenario(b.dataset.scenario);
  });

  $('btn-build').addEventListener('click', doBuild);
  $('btn-rebuild').addEventListener('click', doBuild);

  $('file-certs').addEventListener('change', async (e) => {
    const ders = await readFiles(e.target.files);
    const n = await addBase64Ders(ders, 'file');
    $('cert-file-info').textContent = n ? `已加入 ${n} 张（重复已忽略）` : '无新增（重复或无法识别）';
    scheduleReparse(); await touchInputs();
    e.target.value = '';
  });
  $('file-anchors').addEventListener('change', async (e) => {
    const ders = await readFiles(e.target.files);
    await addBase64Ders(ders, 'anchor-file');
    // Every cert sourced from an anchor file is also designated as a trust anchor.
    for (const c of state.certs) {
      if (c.source === 'anchor-file' && !state.anchorFps.includes(c.fp)) state.anchorFps.push(c.fp);
    }
    scheduleReparse(); await touchInputs();
    e.target.value = '';
  });
  $('btn-add-paste').addEventListener('click', async () => {
    const ders = splitPem($('paste-certs').value);
    const n = await addBase64Ders(ders, 'paste');
    $('paste-certs').value = '';
    if (!n) $('cert-file-info').textContent = '未识别到证书 PEM/base64';
    scheduleReparse(); await touchInputs();
  });
  $('btn-clear-certs').addEventListener('click', async () => {
    state.certs = []; state.anchorFps = []; state.targetFp = null; state.result = null;
    renderInventory(); renderAnchors(); renderTarget(); renderResult(); await touchInputs();
  });

  // inventory delegated actions
  $('cert-inventory').addEventListener('click', async (e) => {
    const row = e.target.closest('.inv-row');
    if (!row) return;
    const fp = row.dataset.fp;
    const action = e.target.dataset.action;
    if (action === 'set-target') { state.targetFp = fp; renderTarget(); await touchInputs(); }
    if (action === 'remove') {
      state.certs = state.certs.filter((c) => c.fp !== fp);
      state.anchorFps = state.anchorFps.filter((x) => x !== fp);
      if (state.targetFp === fp) state.targetFp = state.certs[0]?.fp ?? null;
      scheduleReparse(); renderTarget(); await touchInputs();
    }
  });
  $('cert-inventory').addEventListener('change', async (e) => {
    if (e.target.dataset.action !== 'toggle-anchor') return;
    const fp = e.target.closest('.inv-row').dataset.fp;
    if (e.target.checked) { if (!state.anchorFps.includes(fp)) state.anchorFps.push(fp); }
    else state.anchorFps = state.anchorFps.filter((x) => x !== fp);
    renderInventory(new Map(state.certs.filter((c) => c.view).map((c) => [c.fp, c.view])));
    renderAnchors(); await touchInputs();
  });

  $('anchor-list').addEventListener('click', async (e) => {
    const row = e.target.closest('.anchor-row');
    if (!row) return;
    const fp = row.dataset.fp;
    const i = state.anchorFps.indexOf(fp);
    const action = e.target.dataset.action;
    if (action === 'anchor-up' && i > 0) [state.anchorFps[i - 1], state.anchorFps[i]] = [state.anchorFps[i], state.anchorFps[i - 1]];
    if (action === 'anchor-down' && i < state.anchorFps.length - 1) [state.anchorFps[i + 1], state.anchorFps[i]] = [state.anchorFps[i], state.anchorFps[i + 1]];
    if (action === 'anchor-remove') state.anchorFps.splice(i, 1);
    renderAnchors(); await touchInputs();
  });

  $('target-select').addEventListener('change', async () => {
    state.targetFp = $('target-select').value; await touchInputs();
  });
  $('policy-list').addEventListener('change', async (e) => {
    if (e.target.name !== 'policy') return;
    state.policyId = e.target.value; renderPolicies(); await touchInputs();
  });
  $('verify-at').addEventListener('change', async () => {
    state.verifyAt = fromLocalInput($('verify-at').value); await touchInputs();
  });

  // load the default scenario so the page is useful immediately
  await loadScenario('cross');
}

init().catch((e) => {
  document.body.insertAdjacentHTML('afterbegin',
    `<div style="padding:16px;color:#b00">初始化失败：${esc(e.message)}（确认服务端正在运行）</div>`);
});
