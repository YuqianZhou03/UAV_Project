/**
 * FL-UAV dashboard (English): dataset pipeline story, workflow sim. Data: ../data/rounds_en.json
 */

const pct = (x) => `${(x * 100).toFixed(2)}%`;
const num = (x, d = 2) => (typeof x === "number" && Number.isFinite(x) ? x.toFixed(d) : "—");

/** Structured KV / workflow: integers without .00, non-integers at most 2 decimal places */
function fmtKvNumber(x) {
  if (typeof x !== "number" || !Number.isFinite(x)) return "—";
  const r = Math.round(x);
  if (Math.abs(x - r) < 1e-6 && Math.abs(r) <= 1e15) return String(r);
  return x.toFixed(2);
}

let payload = null;
/** @type {'dataset' | 'workflow'} */
let activeView = "dataset";
/** @type {ReturnType<typeof setTimeout>[]} */
let _wfAnimTimers = [];

function showToast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => el.classList.remove("show"), 3200);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * @param {unknown} val
 * @param {number} depth
 * @returns {string}
 */
function renderValueVisual(val, depth = 0) {
  if (depth > 5) {
    try {
      return `<pre class="kv-fallback mono">${escapeHtml(JSON.stringify(val, null, 2))}</pre>`;
    } catch {
      return `<span class="kv-str">${escapeHtml(String(val))}</span>`;
    }
  }
  if (val === null || val === undefined) {
    return `<span class="kv-null">null</span>`;
  }
  if (typeof val === "boolean") {
    return `<span class="kv-bool ${val ? "kv-bool--t" : "kv-bool--f"}">${val ? "true" : "false"}</span>`;
  }
  if (typeof val === "number") {
    return `<span class="kv-num">${escapeHtml(fmtKvNumber(val))}</span>`;
  }
  if (typeof val === "string") {
    const t = val.length > 160 ? `${val.slice(0, 160)}…` : val;
    return `<span class="kv-str"${val.length > 160 ? ` title="${escapeHtml(val)}"` : ""}>${escapeHtml(t)}</span>`;
  }
  if (Array.isArray(val)) {
    if (val.length === 0) {
      return `<span class="kv-empty">[]</span>`;
    }
    const primitive = (x) =>
      x === null ||
      x === undefined ||
      typeof x === "string" ||
      typeof x === "number" ||
      typeof x === "boolean";
    if (val.every(primitive)) {
      return `<div class="kv-array kv-array--chips">${val
        .map((x) => `<span class="kv-chip">${renderValueVisual(x, depth + 1)}</span>`)
        .join("")}</div>`;
    }
    return `<div class="kv-array kv-array--blocks">${val
      .map((x, i) => `<div class="kv-array-card"><span class="kv-idx">${i}</span>${renderValueVisual(x, depth + 1)}</div>`)
      .join("")}</div>`;
  }
  if (typeof val === "object") {
    const keys = Object.keys(val);
    if (keys.length === 0) {
      return `<span class="kv-empty">{}</span>`;
    }
    return `<div class="kv-obj">${keys
      .map((k) => {
        const v = val[k];
        const isObj = v !== null && typeof v === "object" && !Array.isArray(v) && Object.keys(v).length > 0;
        const isArr = Array.isArray(v) && v.length > 0;
        return `<div class="kv-row${isObj || isArr ? " kv-row--wide" : ""}">
          <span class="kv-key">${escapeHtml(k)}</span>
          <div class="kv-val">${renderValueVisual(v, depth + 1)}</div>
        </div>`;
      })
      .join("")}</div>`;
  }
  return `<span class="kv-str">${escapeHtml(String(val))}</span>`;
}

/** @param {Record<string, unknown>} obj */
function renderStructuredKv(obj) {
  return `<div class="kv-hud" role="region" aria-label="Payload">${renderValueVisual(obj, 0)}</div>`;
}

/** @param {Record<string, unknown>|undefined} cal @param {boolean} langZh */
function workflowIdsCalibrationSummary(cal, langZh) {
  if (!cal || typeof cal !== "object") return null;
  const name = cal.non_attack_argmax_name;
  const id = cal.non_attack_argmax_id;
  const disp = cal.no_alert_display_class != null ? String(cal.no_alert_display_class) : "Normal";
  if (name == null && id == null) return null;
  return langZh
    ? `无告警时 prediction 固定为「${disp}」。告警时 prediction 为模型 argmax（如 MITM、DDoS）。attack_detected 由 argmax 是否等于内部基准 id ${String(id ?? "—")}（典型类名 ${String(name ?? "—")}）决定。`
    : `When clear, prediction is always «${disp}». When alerting, prediction is the argmax class (e.g. MITM). attack_detected compares argmax to internal baseline id ${String(id ?? "—")} (often «${String(name ?? "—")}»).`;
}

/**
 * Show only workflow-useful fields; drop misleading duplicates (per-step timestamps, uplink kind, …).
 * @param {{ id?: string, kv?: Record<string, unknown> } | undefined} step
 * @param {Record<string, unknown>} data
 */
function sanitizeWorkflowStepKv(step, data, langZh) {
  const id = step?.id;
  const kv = step?.kv;
  if (!id || !kv || typeof kv !== "object") return null;
  const cal = data.ids_calibration;

  if (id === "server_config") {
    return {
      run_id: kv.run_id,
      server_round: kv.server_round,
      edge_uav_count: kv.edge_uav_count,
      fit_config_per_uav: kv.fit_config_per_uav,
    };
  }
  if (id === "local_traffic") {
    const per = Array.isArray(kv.per_uav) ? kv.per_uav : [];
    const uavs = per.map((row) => {
      const r = row && typeof row === "object" ? row : {};
      const ben = r.benign_traffic_seed === true;
      return {
        uav_id: r.uav_id,
        batch_window_count: r.batch_size,
        center_sample_row_in_test_npz: r.prototype_index,
        scenario_side: langZh ? (ben ? "良性" : "攻击") : ben ? "benign" : "attack",
        scenario_tag: r.true_label,
        alignment_iterations: r.alignment_iters,
      };
    });
    return {
      traffic_mode: kv.traffic_mode,
      inference_mode: kv.inference_mode,
      checkpoint_loaded: kv.has_checkpoint,
      uavs,
    };
  }
  if (id === "local_verdicts") {
    const uavRows = Array.isArray(kv.uavs) ? kv.uavs : [];
    const note = workflowIdsCalibrationSummary(cal, langZh);
    const uavs = uavRows.map((row) => {
      const r = row && typeof row === "object" ? row : {};
      const ben = r.benign_traffic_seed === true;
      const al = r.attack_label;
      return {
        uav_id: r.uav_id,
        ids_alert: r.attack_detected,
        predicted_class: r.prediction,
        alert_display_class: al != null && String(al).length > 0 ? al : "—",
        scenario_side: langZh ? (ben ? "良性" : "攻击") : ben ? "benign" : "attack",
        scenario_tag: r.true_label,
      };
    });
    const out = { uavs };
    if (note) out.ids_calibration_note = note;
    return out;
  }
  if (id === "uplink") {
    const reps = Array.isArray(kv.reports) ? kv.reports : [];
    const uplink_reports = reps.map((row) => {
      const r = row && typeof row === "object" ? row : {};
      return {
        uav_id: r.uav_id,
        ids_alert: r.attack_detected,
        reported_attack_class: r.attack_class == null ? "—" : r.attack_class,
        center_sample_row_in_test_npz: r.prototype_index,
      };
    });
    return { uplink_reports };
  }
  if (id === "apc") {
    return {
      threat_per_uav: kv.threat_per_uav,
      policy_before_per_uav: kv.policy_before_per_uav,
      policy_after_per_uav: kv.policy_after_per_uav,
    };
  }
  return null;
}

function renderTracebackPanel(text, langZh) {
  const label = langZh ? "堆栈跟踪" : "Traceback";
  return `<div class="kv-hud kv-hud--trace"><div class="kv-trace-head">${escapeHtml(label)}</div><pre class="kv-trace-pre mono">${escapeHtml(String(text))}</pre></div>`;
}

function renderGlossary(glossary) {
  const host = document.getElementById("glossaryList");
  host.innerHTML = "";
  glossary.forEach((g) => {
    const det = document.createElement("details");
    det.className = "glossary-item";
    det.dataset.glossaryId = g.id || "";
    det.innerHTML = `<summary>${escapeHtml(g.term)}</summary><div class="body">${escapeHtml(g.body)}</div>`;
    host.appendChild(det);
  });
}

function setMainPanels(view) {
  const isWorkflow = view === "workflow";
  const isDataset = view === "dataset";
  const ds = document.getElementById("viewDataset");
  if (ds) ds.classList.toggle("is-hidden", !isDataset);
  const wf = document.getElementById("viewWorkflow");
  if (wf) wf.classList.toggle("is-hidden", !isWorkflow);
}

function navSetActive(view) {
  document.querySelectorAll(".round-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.view === view);
  });
}

function injectArchDiagram() {
  const host = document.getElementById("archDiagramHost");
  host.innerHTML = `
<svg class="arch-svg" viewBox="0 0 920 300" xmlns="http://www.w3.org/2000/svg" aria-label="Four-component federated learning and privacy loop">
  <defs>
    <marker id="arrowHead" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <polygon points="0 0, 8 4, 0 8" fill="rgba(56,189,248,0.9)" />
    </marker>
    <marker id="arrowHeadDim" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
      <polygon points="0 0, 8 4, 0 8" fill="rgba(140,163,201,0.85)" />
    </marker>
  </defs>
  <rect class="box box-accent" x="24" y="88" width="168" height="124" rx="3" />
  <text class="title" x="108" y="118" text-anchor="middle">UAV edge clients ×3</text>
  <text class="sub" x="108" y="138" text-anchor="middle">client.py · DroneClient</text>
  <text class="sub" x="108" y="156" text-anchor="middle">NumPyClient · gRPC</text>
  <text class="sub" x="108" y="178" text-anchor="middle">Local CNN+LSTM · train_split</text>

  <rect class="box box-accent" x="236" y="64" width="236" height="172" rx="3" />
  <text class="title" x="354" y="98" text-anchor="middle">Flower federated server</text>
  <text class="sub" x="354" y="118" text-anchor="middle">server.py · FedAvg</text>
  <text class="sub" x="354" y="136" text-anchor="middle">Centralized IDS · CnnLstmIDS</text>
  <text class="sub" x="354" y="154" text-anchor="middle">test.npz · global holdout</text>
  <text class="sub" x="354" y="178" text-anchor="middle">Next-round fit config</text>

  <rect class="box" x="512" y="88" width="168" height="124" rx="3" />
  <text class="title" x="596" y="118" text-anchor="middle">RL trust bridge</text>
  <text class="sub" x="596" y="138" text-anchor="middle">RL_module</text>
  <text class="sub" x="596" y="156" text-anchor="middle">FLTrustRLBridge</text>
  <text class="sub" x="596" y="178" text-anchor="middle">Trust 0–100 · fleet state</text>

  <rect class="box" x="712" y="88" width="184" height="124" rx="3" />
  <text class="title" x="804" y="118" text-anchor="middle">APC policy</text>
  <text class="sub" x="804" y="138" text-anchor="middle">apc_module</text>
  <text class="sub" x="804" y="156" text-anchor="middle">AdaptivePrivacyController</text>
  <text class="sub" x="804" y="178" text-anchor="middle">participate · noise · 1/N uplink</text>

  <line class="edge" x1="192" y1="150" x2="236" y2="150" />
  <text class="edge-label" x="214" y="142" text-anchor="middle">gRPC</text>

  <line class="edge" x1="472" y1="150" x2="512" y2="150" />
  <text class="edge-label" x="492" y="142" text-anchor="middle">eval summary</text>

  <line class="edge" x1="680" y1="150" x2="712" y2="150" />
  <text class="edge-label" x="696" y="142" text-anchor="middle">trust in</text>

  <path class="edge-back" d="M 804 212 C 804 248, 380 260, 354 236" />
  <text class="edge-label" x="548" y="268" text-anchor="middle">Policy feedback (dashed)</text>

  <text class="legend" x="24" y="288">Solid: data &amp; control · Dashed: APC → Server → next on_fit_config</text>
</svg>`;
}

function clearWorkflowAnimTimers() {
  _wfAnimTimers.forEach((id) => clearTimeout(id));
  _wfAnimTimers = [];
}

function resetWorkflowSceneVisual() {
  const host = document.getElementById("workflowSceneHost");
  if (!host) return;
  clearWorkflowAnimTimers();
  host.querySelectorAll(".wf-phase").forEach((el) => el.classList.remove("wf-phase--active"));
  host.querySelectorAll(".wf-drone").forEach((el) => {
    el.classList.remove("wf-drone--alert", "wf-drone--ok", "wf-drone--scan");
  });
  host.classList.remove("workflow-scene-host--error");
  const cap = host.querySelector("#wfLiveCaption");
  if (cap) cap.textContent = "";
}

function setWorkflowCaption(_langZh, text) {
  const el = document.querySelector("#wfLiveCaption");
  if (!el) return;
  el.textContent = text;
  if (text.length > 72) {
    el.setAttribute("textLength", "920");
    el.setAttribute("lengthAdjust", "spacingAndGlyphs");
  } else {
    el.removeAttribute("textLength");
    el.removeAttribute("lengthAdjust");
  }
}

/** @param {string|number} k @param {{ participate?: number; noise_scale?: number; freq_n?: number }} pol @param {boolean} langZh */
function formatApcPolicyLine(k, pol, langZh) {
  const ns = typeof pol.noise_scale === "number" ? pol.noise_scale.toFixed(2) : String(pol.noise_scale ?? "—");
  const pr = Number(pol.participate);
  const fn = Number(pol.freq_n);
  if (langZh) {
    const part = pr === 1 ? "参与" : "停";
    const fq = pr === 1 && Number.isFinite(fn) ? `1/${fn}轮` : "—";
    return `UAV${k} ${part}·n${ns}·${fq}`;
  }
  const part = pr === 1 ? "on" : "off";
  const fq = pr === 1 && Number.isFinite(fn) ? `1/${fn}r` : "—";
  return `U${k} ${part}·n${ns}·${fq}`;
}

function renderWorkflowBaseDiagram(langZh) {
  const host = document.getElementById("workflowSceneHost");
  if (!host) return;
  clearWorkflowAnimTimers();
  const zh = langZh;
  const t = zh
    ? {
        leg: "三架无人机（边缘） ⟷ 联邦服务器：参数下发 · 本地 IDS · 上行 · APC 回注",
        idle: "点击「运行一次完整流程」播放交互动画",
        srv: "联邦服务器",
        sub: "Flower · gRPC",
        apc: "APC",
        apcSub: "freq_n＝每 N 轮上传一次 · participate 停/参与",
        lCfg: "① 下发 fit 参数",
        lLoc: "② 本地流量 IDS",
        lUp: "③ 上行安全上报",
        lRet: "④ 策略回注各机",
        u0: "无人机 0",
        u1: "无人机 1",
        u2: "无人机 2",
      }
    : {
        leg: "Three edge UAVs ⟷ federated server: config · local IDS · uplink · APC feedback",
        idle: 'Use steps ①→③ to run the workflow',
        srv: "Federated server",
        sub: "Flower · gRPC",
        apc: "APC",
        apcSub: "freq_n = uplink every N rounds · participate on/off",
        lCfg: "① Downlink fit config",
        lLoc: "② Local traffic IDS",
        lUp: "③ Uplink security report",
        lRet: "④ Policy back to UAVs",
        u0: "UAV 0",
        u1: "UAV 1",
        u2: "UAV 2",
      };

  const drone = (x, y, id, label) => `<g class="wf-drone" id="wf-drone-${id}" transform="translate(${x},${y})">
    <ellipse class="wf-prop" cx="-22" cy="-8" rx="13" ry="4" />
    <ellipse class="wf-prop" cx="22" cy="-8" rx="13" ry="4" />
    <path class="wf-fuselage" d="M-30 6 L0 -22 L30 6 Z" />
    <ellipse class="wf-deck" cx="0" cy="10" rx="32" ry="11" />
    <circle class="wf-hub" cx="0" cy="-4" r="5" />
    <text class="wf-uav-label" x="0" y="44" text-anchor="middle">${escapeHtml(label)}</text>
  </g>`;

  host.innerHTML = `<svg class="workflow-scene-svg" viewBox="0 0 1000 440" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${escapeHtml(t.leg)}">
  <defs>
    <marker id="wfmCfg" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" class="wf-mar"/></marker>
    <marker id="wfmUp" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" class="wf-mar-up"/></marker>
  </defs>
  <rect class="wf-sky" width="1000" height="440"/>
  <text id="wfLiveCaption" class="wf-live-cap" x="500" y="30" text-anchor="middle">${escapeHtml(t.idle)}</text>
  <text class="wf-legend" x="24" y="56">${escapeHtml(t.leg)}</text>
  <line class="wf-ground" x1="0" y1="372" x2="620" y2="372"/>

  <g id="wf-drones" class="wf-phase wf-phase-local">
    ${drone(110, 308, 0, t.u0)}
    ${drone(270, 308, 1, t.u1)}
    ${drone(430, 308, 2, t.u2)}
  </g>

  <g class="wf-srv">
    <rect class="wf-srv-shade" x="632" y="56" width="348" height="328" rx="16"/>
    <rect class="wf-srv-body" x="644" y="68" width="324" height="304" rx="12"/>
    <text class="wf-srv-title" x="806" y="104" text-anchor="middle">${escapeHtml(t.srv)}</text>
    <text class="wf-srv-sub" x="806" y="124" text-anchor="middle">${escapeHtml(t.sub)}</text>
    <rect class="wf-apc-box wf-phase wf-phase-apc" x="664" y="232" width="284" height="120" rx="10"/>
    <text class="wf-apc-t" x="806" y="268" text-anchor="middle">${escapeHtml(t.apc)}</text>
    <text class="wf-apc-sub" x="806" y="290" text-anchor="middle">${escapeHtml(t.apcSub)}</text>
  </g>

  <g class="wf-phase wf-phase-config">
    <path class="wf-edge wf-e-c0" data-edge-tip="${escapeHtml(zh ? "下发参数（UAV0）：participate, noise_scale, freq_n" : "Downlink params (UAV0): participate, noise_scale, freq_n")}" d="M 664 150 C 500 90, 200 120, 110 292" marker-end="url(#wfmCfg)"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-c0" data-edge-tip="${escapeHtml(zh ? "下发参数（UAV0）：participate, noise_scale, freq_n" : "Downlink params (UAV0): participate, noise_scale, freq_n")}" d="M 664 150 C 500 90, 200 120, 110 292"/>
    <path class="wf-edge wf-e-c1" data-edge-tip="${escapeHtml(zh ? "下发参数（UAV1）：participate, noise_scale, freq_n" : "Downlink params (UAV1): participate, noise_scale, freq_n")}" d="M 664 175 C 520 130, 300 140, 270 292" marker-end="url(#wfmCfg)"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-c1" data-edge-tip="${escapeHtml(zh ? "下发参数（UAV1）：participate, noise_scale, freq_n" : "Downlink params (UAV1): participate, noise_scale, freq_n")}" d="M 664 175 C 520 130, 300 140, 270 292"/>
    <path class="wf-edge wf-e-c2" data-edge-tip="${escapeHtml(zh ? "下发参数（UAV2）：participate, noise_scale, freq_n" : "Downlink params (UAV2): participate, noise_scale, freq_n")}" d="M 664 200 C 560 170, 400 160, 430 292" marker-end="url(#wfmCfg)"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-c2" data-edge-tip="${escapeHtml(zh ? "下发参数（UAV2）：participate, noise_scale, freq_n" : "Downlink params (UAV2): participate, noise_scale, freq_n")}" d="M 664 200 C 560 170, 400 160, 430 292"/>
    <text class="wf-edge-label" x="340" y="102">${escapeHtml(t.lCfg)}</text>
  </g>
  <g class="wf-phase wf-phase-uplink">
    <path class="wf-edge wf-e-u0" data-edge-tip="${escapeHtml(zh ? "上行参数（UAV0）：attack_detected, prediction, attack_label, attack_vote_ratio" : "Uplink params (UAV0): attack_detected, prediction, attack_label, attack_vote_ratio")}" d="M 130 285 Q 420 160 806 198" marker-end="url(#wfmUp)"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-u0" data-edge-tip="${escapeHtml(zh ? "上行参数（UAV0）：attack_detected, prediction, attack_label, attack_vote_ratio" : "Uplink params (UAV0): attack_detected, prediction, attack_label, attack_vote_ratio")}" d="M 130 285 Q 420 160 806 198"/>
    <path class="wf-edge wf-e-u1" data-edge-tip="${escapeHtml(zh ? "上行参数（UAV1）：attack_detected, prediction, attack_label, attack_vote_ratio" : "Uplink params (UAV1): attack_detected, prediction, attack_label, attack_vote_ratio")}" d="M 290 285 Q 460 175 806 210" marker-end="url(#wfmUp)"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-u1" data-edge-tip="${escapeHtml(zh ? "上行参数（UAV1）：attack_detected, prediction, attack_label, attack_vote_ratio" : "Uplink params (UAV1): attack_detected, prediction, attack_label, attack_vote_ratio")}" d="M 290 285 Q 460 175 806 210"/>
    <path class="wf-edge wf-e-u2" data-edge-tip="${escapeHtml(zh ? "上行参数（UAV2）：attack_detected, prediction, attack_label, attack_vote_ratio" : "Uplink params (UAV2): attack_detected, prediction, attack_label, attack_vote_ratio")}" d="M 450 285 Q 500 210 806 222" marker-end="url(#wfmUp)"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-u2" data-edge-tip="${escapeHtml(zh ? "上行参数（UAV2）：attack_detected, prediction, attack_label, attack_vote_ratio" : "Uplink params (UAV2): attack_detected, prediction, attack_label, attack_vote_ratio")}" d="M 450 285 Q 500 210 806 222"/>
    <text class="wf-edge-label wf-edge-label-up" x="420" y="150">${escapeHtml(t.lUp)}</text>
  </g>
  <g class="wf-phase wf-phase-return">
    <path class="wf-edge wf-e-r0" data-edge-tip="${escapeHtml(zh ? "回注参数（UAV0）：participate, noise_scale, freq_n" : "Return params (UAV0): participate, noise_scale, freq_n")}" d="M 806 248 C 480 400, 220 360, 130 318"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-r0" data-edge-tip="${escapeHtml(zh ? "回注参数（UAV0）：participate, noise_scale, freq_n" : "Return params (UAV0): participate, noise_scale, freq_n")}" d="M 806 248 C 480 400, 220 360, 130 318"/>
    <path class="wf-edge wf-e-r1" data-edge-tip="${escapeHtml(zh ? "回注参数（UAV1）：participate, noise_scale, freq_n" : "Return params (UAV1): participate, noise_scale, freq_n")}" d="M 806 258 C 500 410, 300 368, 290 318"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-r1" data-edge-tip="${escapeHtml(zh ? "回注参数（UAV1）：participate, noise_scale, freq_n" : "Return params (UAV1): participate, noise_scale, freq_n")}" d="M 806 258 C 500 410, 300 368, 290 318"/>
    <path class="wf-edge wf-e-r2" data-edge-tip="${escapeHtml(zh ? "回注参数（UAV2）：participate, noise_scale, freq_n" : "Return params (UAV2): participate, noise_scale, freq_n")}" d="M 806 268 C 540 418, 420 378, 450 318"/>
    <path class="wf-edge-hit" data-hit-for="wf-e-r2" data-edge-tip="${escapeHtml(zh ? "回注参数（UAV2）：participate, noise_scale, freq_n" : "Return params (UAV2): participate, noise_scale, freq_n")}" d="M 806 268 C 540 418, 420 378, 450 318"/>
    <text class="wf-edge-label" x="520" y="408">${escapeHtml(t.lRet)}</text>
  </g>
  <text class="wf-edge-label wf-loc-hint" x="270" y="402">${escapeHtml(t.lLoc)}</text>
</svg>`;
  bindWorkflowEdgeTooltips();
  host.classList.remove("workflow-scene-host--error");
}

function bindWorkflowEdgeTooltips() {
  const host = document.getElementById("workflowSceneHost");
  if (!host) return;
  let tip = host.querySelector(".workflow-edge-tip");
  if (!tip) {
    tip = document.createElement("div");
    tip.className = "workflow-edge-tip";
    host.appendChild(tip);
  }
  const setHover = (edge, on) => {
    const k = edge.getAttribute("data-hit-for");
    const target = k ? host.querySelector(`.wf-edge.${k}`) : edge;
    if (!target) return;
    target.classList.toggle("is-hover", !!on);
  };
  const hide = () => tip.classList.remove("is-show");
  const move = (ev) => {
    const rect = host.getBoundingClientRect();
    const w = tip.offsetWidth || 220;
    const h = tip.offsetHeight || 48;
    const maxX = Math.max(8, rect.width - w - 8);
    const maxY = Math.max(8, rect.height - h - 8);
    const x = Math.min(maxX, Math.max(8, ev.clientX - rect.left + 12));
    const y = Math.min(maxY, Math.max(8, ev.clientY - rect.top + 12));
    tip.style.left = `${x}px`;
    tip.style.top = `${y}px`;
  };
  host.querySelectorAll(".wf-edge[data-edge-tip], .wf-edge-hit[data-edge-tip]").forEach((edge) => {
    edge.style.cursor = "pointer";
    edge.addEventListener("mouseenter", (ev) => {
      setHover(edge, true);
      tip.textContent = edge.getAttribute("data-edge-tip") || "";
      tip.classList.add("is-show");
      move(ev);
    });
    edge.addEventListener("mousemove", move);
    edge.addEventListener("mouseleave", () => {
      setHover(edge, false);
      hide();
    });
  });
  host.querySelector(".workflow-scene-svg")?.addEventListener("mouseleave", () => {
    host.querySelectorAll(".wf-edge.is-hover").forEach((el) => el.classList.remove("is-hover"));
    hide();
  });
}

function animateWorkflowDiagram(data, langZh) {
  const host = document.getElementById("workflowSceneHost");
  if (!host || !data.ok) return;
  resetWorkflowSceneVisual();
  const zh = langZh;
  const cal = data.ids_calibration && typeof data.ids_calibration === "object" ? data.ids_calibration : {};
  const displayNormal = cal.no_alert_display_class != null ? String(cal.no_alert_display_class) : "Normal";
  const cap = {
    cfg: zh ? "① 服务器向三机下发 fit 配置…" : "① Server pushes fit config to 3 UAVs…",
    loc: zh ? "② 三机并行：各自流量窗口 + 本地 IDS…" : "② Three UAVs: local IDS on own traffic…",
    atk: zh ? "③ 发现攻击：" : "③ Attack detected:",
    ok: zh ? `③ 无告警（展示 ${displayNormal}）` : `③ No alert (shown as ${displayNormal})`,
    up: zh ? "④ 三路上报服务器…" : "④ Three uplinks to server…",
    apc: zh ? "⑤ APC 分机策略 → 下发各机…" : "⑤ APC per-UAV policy → push to each…",
  };
  const steps = data.steps || [];
  const find = (id) => steps.find((s) => s.id === id);
  const uavList = Array.isArray(data.uavs) ? data.uavs : [];
  let delay = 0;
  const run = (ms, fn) => {
    _wfAnimTimers.push(setTimeout(fn, ms));
  };

  if (find("server_config")) {
    run(delay, () => {
      host.querySelector(".wf-phase-config")?.classList.add("wf-phase--active");
      setWorkflowCaption(langZh, cap.cfg);
    });
    delay += 520;
  }
  if (find("local_traffic")) {
    run(delay, () => {
      host.querySelector(".wf-phase-config")?.classList.remove("wf-phase--active");
      host.querySelector("#wf-drones")?.classList.add("wf-phase--active");
      host.querySelectorAll(".wf-drone").forEach((d) => d.classList.add("wf-drone--scan"));
      setWorkflowCaption(langZh, cap.loc);
    });
    delay += 580;
  }
  const atkStep = find("local_alert");
  const okStep = find("local_ok");
  const verdictStep = find("local_verdicts");
  if (uavList.length || verdictStep || atkStep || okStep) {
    run(delay, () => {
      host.querySelector("#wf-drones")?.classList.remove("wf-phase--active");
      host.querySelectorAll(".wf-drone").forEach((d) => d.classList.remove("wf-drone--scan"));
      if (uavList.length) {
        uavList.forEach((u) => {
          const el = host.querySelector(`#wf-drone-${u.uav_id}`);
          if (!el) return;
          if (u.attack_detected) el.classList.add("wf-drone--alert");
          else el.classList.add("wf-drone--ok");
        });
        const parts = uavList.map((u) => {
          if (u.attack_detected) {
            return zh ? `机${u.uav_id}:${u.attack_label || "?"}` : `U${u.uav_id}:${u.attack_label || "?"}`;
          }
          return zh ? `机${u.uav_id}:无告警(${displayNormal})` : `U${u.uav_id}:clear(${displayNormal})`;
        });
        setWorkflowCaption(langZh, (zh ? "③ 三机判定：" : "③ Per-UAV: ") + parts.join(zh ? " ｜ " : " | "));
      } else if (atkStep) {
        host.querySelectorAll(".wf-drone").forEach((d) => d.classList.add("wf-drone--alert"));
        const nm = data.attack_label || "";
        setWorkflowCaption(langZh, cap.atk + (nm ? ` ${nm}` : ""));
      } else {
        host.querySelectorAll(".wf-drone").forEach((d) => d.classList.add("wf-drone--ok"));
        setWorkflowCaption(langZh, cap.ok);
      }
    });
    delay += 680;
  }
  if (find("uplink")) {
    run(delay, () => {
      host.querySelectorAll(".wf-drone").forEach((d) => d.classList.remove("wf-drone--alert", "wf-drone--ok"));
      host.querySelector(".wf-phase-uplink")?.classList.add("wf-phase--active");
      setWorkflowCaption(langZh, cap.up);
    });
    delay += 580;
  }
  if (find("apc")) {
    const apcStep = find("apc");
    run(delay, () => {
      host.querySelector(".wf-phase-uplink")?.classList.remove("wf-phase--active");
      host.querySelector(".wf-phase-apc")?.classList.add("wf-phase--active");
      host.querySelector(".wf-phase-return")?.classList.add("wf-phase--active");
      let line = cap.apc;
      const perPol = apcStep?.kv?.policy_after_per_uav;
      const pol = apcStep?.kv?.policy_after;
      if (perPol && typeof perPol === "object") {
        const keys = Object.keys(perPol).sort((a, b) => Number(a) - Number(b));
        const bits = keys.map((k) => formatApcPolicyLine(k, perPol[k], langZh));
        line += zh ? ` → ` : ` → `;
        line += bits.join(zh ? " ｜ " : " | ");
      } else if (pol && typeof pol === "object") {
        const ns = typeof pol.noise_scale === "number" ? pol.noise_scale.toFixed(2) : String(pol.noise_scale);
        line += zh
          ? ` → p${pol.participate} · n${ns} · 1/${pol.freq_n}轮`
          : ` → p${pol.participate} · n${ns} · 1/${pol.freq_n}r`;
      }
      setWorkflowCaption(langZh, line);
    });
    delay += 700;
  }
  run(delay + 200, () => {
    host.querySelector(".wf-phase-return")?.classList.remove("wf-phase--active");
    host.querySelector(".wf-phase-apc")?.classList.remove("wf-phase--active");
    if (uavList.length) {
      uavList.forEach((u) => {
        const el = host.querySelector(`#wf-drone-${u.uav_id}`);
        if (!el) return;
        el.classList.remove("wf-drone--alert", "wf-drone--ok");
        if (u.attack_detected) el.classList.add("wf-drone--alert");
        else el.classList.add("wf-drone--ok");
      });
    } else if (data.attack_detected) {
      host.querySelectorAll(".wf-drone").forEach((d) => d.classList.add("wf-drone--alert"));
    }
    setWorkflowCaption(langZh, zh ? "动画结束 — 详情见下方步骤" : "Animation done — see steps below");
  });
}

function applyWorkflow() {
  activeView = "workflow";
  destroyTheatreMaps();
  setMainPanels("workflow");
  navSetActive("workflow");
  const steps = document.getElementById("workflowSteps");
  const st = document.getElementById("workflowStatus");
  if (steps) steps.innerHTML = "";
  if (st) {
    st.textContent = "";
    st.classList.remove("is-error");
  }
  ["workflowStartServerBtn", "workflowStartClientsBtn", "workflowTrainBtn"].forEach((id) => {
    const b = document.getElementById(id);
    if (b) b.disabled = false;
  });
  renderWorkflowBaseDiagram(false);
}

function renderWorkflowStepCards(steps, data, langZh, append = false) {
  const host = document.getElementById("workflowSteps");
  if (!host) return;
  const html = (steps || [])
    .map((s) => {
      const title = langZh ? s.title_zh : s.title_en;
      const body = langZh ? s.body_zh : s.body_en;
      const bodyHtml = escapeHtml(body || "").replace(/\n/g, "<br/>");
      let kv = "";
      if (s.kv && typeof s.kv === "object") {
        const cleaned = sanitizeWorkflowStepKv(s, data || {}, langZh) || s.kv;
        if (cleaned && typeof cleaned === "object" && Object.keys(cleaned).length > 0) {
          kv = renderStructuredKv(cleaned);
        }
      }
      return `<article class="workflow-step"><h4>${escapeHtml(title || "")}</h4><p class="workflow-step-body">${bodyHtml}</p>${kv}</article>`;
    })
    .join("");
  if (append) host.insertAdjacentHTML("beforeend", html);
  else host.innerHTML = html;
}

function renderWorkflowResult(data, langZh) {
  const st = document.getElementById("workflowStatus");
  const scene = document.getElementById("workflowSceneHost");
  if (!st) return;
  if (!data.ok) {
    st.textContent = (langZh ? "错误：" : "Error: ") + (data.error || "—");
    st.classList.add("is-error");
    if (scene) {
      scene.classList.add("workflow-scene-host--error");
      renderWorkflowBaseDiagram(langZh);
      setWorkflowCaption(langZh, langZh ? "模拟失败 — 请检查终端或依赖数据" : "Simulation failed — check console / data");
    }
    const host = document.getElementById("workflowSteps");
    if (host) host.innerHTML = data.traceback ? renderTracebackPanel(data.traceback, langZh) : "";
    return;
  }
  if (scene) scene.classList.remove("workflow-scene-host--error");
  st.classList.remove("is-error");
  const mode = data.inference_mode || "—";
  const atk = data.attack_detected;
  const label = data.attack_label || "";
  const cal = data.ids_calibration && typeof data.ids_calibration === "object" ? data.ids_calibration : null;
  const displayCls = cal && cal.no_alert_display_class != null ? String(cal.no_alert_display_class) : "Normal";
  const calLine = langZh ? ` · 无告警展示：${displayCls}` : ` · No-alert display: ${displayCls}`;
  const runExtra =
    data.run_id != null && String(data.run_id).length > 0
      ? langZh
        ? ` · run_id=${data.run_id}`
        : ` · run_id=${data.run_id}`
      : "";
  const nu = typeof data.num_uavs === "number" ? data.num_uavs : null;
  const ua = typeof data.uavs_alerting === "number" ? data.uavs_alerting : null;
  const fleetExtra =
    nu != null && ua != null
      ? langZh
        ? ` · 告警架数 ${ua}/${nu}`
        : ` · Alerting ${ua}/${nu}`
      : "";
  st.textContent = langZh
    ? `推理：${mode}${calLine} · 任一架告警：${atk ? "是" : "否"}${label ? " · " + label : ""}${fleetExtra}${runExtra}`
    : `Inference: ${mode}${calLine} · Any alert: ${atk ? "yes" : "no"}${label ? " · " + label : ""}${fleetExtra}${runExtra}`;

  renderWorkflowStepCards(data.steps || [], data, langZh, false);
  animateWorkflowDiagram(data, langZh);
}

async function runWorkflowStage(action, langZh) {
  const btnMap = {
    start_server: "workflowStartServerBtn",
    start_clients: "workflowStartClientsBtn",
    start_training: "workflowTrainBtn",
  };
  const btn = document.getElementById(btnMap[action] || "");
  if (!btn) return;
  btn.disabled = true;
  if (action === "start_server") {
    clearWorkflowAnimTimers();
    renderWorkflowBaseDiagram(langZh);
    const host = document.getElementById("workflowSteps");
    const st = document.getElementById("workflowStatus");
    if (host) host.innerHTML = "";
    if (st) {
      st.textContent = "";
      st.classList.remove("is-error");
    }
  }
  try {
    const res = await fetch(`/api/fl-control?action=${encodeURIComponent(action)}&mode=auto&_=${Date.now()}`, {
      cache: "no-store",
    });
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      const t = text.trimStart();
      const looksHtml = t.startsWith("<") || t.toLowerCase().includes("<!doctype");
      const msg = langZh
        ? looksHtml
          ? `HTTP ${res.status}：返回了网页而不是 JSON，说明当前站点没有提供 /api/fl-control。请在仓库根目录执行「python dashboard/serve.py」再打开终端里打印的地址。`
          : `HTTP ${res.status}：响应不是合法 JSON。开头：${t.slice(0, 96).replace(/\s+/g, " ")}`
        : looksHtml
          ? `HTTP ${res.status}: received HTML, not JSON — /api/fl-control is not available. Run \`python dashboard/serve.py\` from the repo root.`
          : `HTTP ${res.status}: body is not valid JSON. Start: ${t.slice(0, 96).replace(/\s+/g, " ")}`;
      renderWorkflowResult({ ok: false, error: msg }, langZh);
      return;
    }
    const st = document.getElementById("workflowStatus");
    if (action === "start_training") {
      clearWorkflowAnimTimers();
      renderWorkflowBaseDiagram(langZh);
      renderWorkflowResult(data, langZh);
    } else {
      if (st) {
        st.classList.remove("is-error");
        if (action === "start_server") {
          st.textContent = "Server terminal started.";
        } else if (action === "start_clients") {
          st.textContent = "Three UAV terminals started.";
        } else {
          st.textContent = "Step finished.";
        }
      }
      if (data.phase_step) renderWorkflowStepCards([data.phase_step], data, langZh, true);
      const host = document.getElementById("workflowSceneHost");
      if (host) {
        if (action === "start_server") {
          host.querySelector(".wf-phase-config")?.classList.add("wf-phase--active");
          setWorkflowCaption(langZh, langZh ? "① 服务器已启动，等待三机连接…" : "① Server started, waiting for UAV clients…");
        } else if (action === "start_clients") {
          host.querySelector(".wf-phase-config")?.classList.remove("wf-phase--active");
          host.querySelector("#wf-drones")?.classList.add("wf-phase--active");
          host.querySelectorAll(".wf-drone").forEach((d) => d.classList.add("wf-drone--scan"));
          setWorkflowCaption(
            langZh,
            langZh ? "② 三机终端已启动，准备训练…" : "② Three UAV terminals started, ready for training…",
          );
        }
      }
    }
  } catch (e) {
    renderWorkflowResult({ ok: false, error: String(e) }, langZh);
  } finally {
    btn.disabled = false;
  }
}

/** @type {unknown[]} */
let theatreMaps = [];

function destroyTheatreMaps() {
  for (const m of theatreMaps) {
    try {
      if (m && typeof m.remove === "function") m.remove();
    } catch (_) {
      /* ignore */
    }
  }
  theatreMaps = [];
}

function initTheatreMaps() {
  const L = globalThis.L;
  const list = payload?.theatres;
  if (!list || !list.length) return;

  if (!L || typeof L.map !== "function") {
    document.querySelectorAll(".theatre-map").forEach((el) => {
      el.innerHTML =
        '<p class="map-fallback">Leaflet failed to load (network or blocker). Map unavailable.</p>';
    });
    return;
  }

  const zoomByRound = { 1: 5, 2: 4, 3: 5 };

  for (const t of list) {
    const el = document.getElementById(`map-theatre-${t.flRound}`);
    if (!el) continue;

    const map = L.map(el, {
      scrollWheelZoom: false,
      zoomControl: true,
      attributionControl: true,
    }).setView([t.latitude_deg, t.longitude_deg], zoomByRound[t.flRound] ?? 5);

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: "abcd",
      maxZoom: 20,
    }).addTo(map);

    L.circleMarker([t.latitude_deg, t.longitude_deg], {
      radius: 7,
      color: "#38bdf8",
      fillColor: "#38bdf8",
      fillOpacity: 0.88,
      weight: 2,
    })
      .addTo(map)
      .bindPopup(
        `<strong>${escapeHtml(t.cardTitle)}</strong><br><span class="mono">${escapeHtml(t.gps_wgs84)}</span>`,
      );

    theatreMaps.push(map);
  }

  const invalidateAll = () => {
    theatreMaps.forEach((m) => {
      try {
        if (m && typeof m.invalidateSize === "function") m.invalidateSize();
      } catch (_) {
        /* ignore */
      }
    });
  };
  queueMicrotask(() => {
    setTimeout(invalidateAll, 120);
    setTimeout(invalidateAll, 450);
  });
}

function renderTheatres() {
  destroyTheatreMaps();
  const grid = document.getElementById("theatreGrid");
  const list = payload.theatres || [];
  grid.innerHTML = list
    .map((t) => {
      return `<article class="theatre-card">
        <p class="flr">Scenario ${t.flRound}</p>
        <h4 class="city">${escapeHtml(t.cardTitle)}</h4>
        <p class="place">${escapeHtml(t.cardSubtitle)}</p>
        <p class="region">${escapeHtml(t.region)}</p>
        <p class="gps">${escapeHtml(t.gps_wgs84)}</p>
        <p class="scene">${escapeHtml(t.scene)}</p>
        <div class="theatre-map" id="map-theatre-${t.flRound}" aria-label="Map: ${escapeHtml(t.cardTitle)}"></div>
        <p class="map-caption">Basemap via CARTO Dark + OSM (requires internet). Zoom controls; click the marker for coordinates.</p>
      </article>`;
    })
    .join("");

  requestAnimationFrame(() => {
    initTheatreMaps();
  });
}

function latestDemoRound() {
  const rs = payload?.rounds;
  if (!Array.isArray(rs) || rs.length === 0) return null;
  return rs.reduce((best, r) => (r.id > best.id ? r : best));
}

function renderDatasetEval() {
  const host = document.getElementById("datasetEvalGrid");
  if (!host) return;
  const round = latestDemoRound();
  if (!round?.centralized) {
    host.innerHTML = `<p class="panel-lead" style="margin:0">No centralized eval in snapshot.</p>`;
    return;
  }
  const c = round.centralized;
  const cards = [
    { v: pct(c.accuracy), l: "Global accuracy" },
    { v: num(c.loss, 2), l: "Cross-entropy loss" },
    { v: pct(c.precision_macro), l: "Macro precision" },
    { v: pct(c.recall_macro), l: "Macro recall" },
    { v: String(c.test_windows), l: "Test windows" },
  ];
  host.innerHTML = `${cards
    .map(
      (x) => `<div class="metric-card"><div class="v">${x.v}</div><div class="l">${escapeHtml(x.l)}</div></div>`,
    )
    .join("")}
    <p class="tiny mono" style="grid-column:1/-1;margin:0.6rem 0 0;color:var(--text-dim)">Snapshot round: ${escapeHtml(round.label)} (id=${round.id})</p>`;
}

function applyDataset() {
  activeView = "dataset";
  destroyTheatreMaps();
  setMainPanels("dataset");
  navSetActive("dataset");
  renderDatasetEval();
}

function bindNavButtons() {
  const host = document.getElementById("roundButtons");
  host.innerHTML = "";

  const ds = document.createElement("button");
  ds.type = "button";
  ds.className = "round-btn active";
  ds.dataset.view = "dataset";
  ds.textContent = "Dataset";
  ds.title = "UAV-NIDD provenance, cleaning, CNN+LSTM inputs, demo accuracy";
  ds.addEventListener("click", () => applyDataset());
  host.appendChild(ds);

  const wf = document.createElement("button");
  wf.type = "button";
  wf.className = "round-btn";
  wf.dataset.view = "workflow";
  wf.textContent = "Workflow";
  wf.title = "One click: server params → local IDS on traffic → report → APC policy";
  wf.addEventListener("click", () => applyWorkflow());
  host.appendChild(wf);
}

function bindHintButtons() {
  document.querySelectorAll(".hint-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-glossary-id");
      const sel = document.querySelector(`details.glossary-item[data-glossary-id="${id}"]`);
      if (sel) {
        sel.open = true;
        sel.scrollIntoView({ behavior: "smooth", block: "nearest" });
        showToast("Opened the matching glossary entry on the right.");
      }
    });
  });
}

async function init() {
  try {
    const res = await fetch("../data/rounds_en.json", { cache: "no-store" });
    if (!res.ok) throw new Error(res.statusText);
    payload = await res.json();
    try {
      const lr = await fetch("../data/live_rounds.json", { cache: "no-store" });
      if (lr.ok) {
        const live = await lr.json();
        if (Array.isArray(live.rounds) && live.rounds.length > 0) {
          payload.rounds = live.rounds;
        }
      }
    } catch {
      /* keep bundled demo rounds */
    }

    const b1 = document.getElementById("workflowStartServerBtn");
    if (b1) b1.addEventListener("click", () => runWorkflowStage("start_server", false));
    const b2 = document.getElementById("workflowStartClientsBtn");
    if (b2) b2.addEventListener("click", () => runWorkflowStage("start_clients", false));
    const b3 = document.getElementById("workflowTrainBtn");
    if (b3) b3.addEventListener("click", () => runWorkflowStage("start_training", false));
  } catch (e) {
    document.getElementById("mainContent").innerHTML =
      `<div class="panel"><p class="panel-lead">Could not load <code>../data/rounds_en.json</code>. Run <code>python dashboard/serve.py</code> from the repository root and open <code>http://127.0.0.1:8765/en/</code> (includes <code>/api/fl-control</code>).</p><p class="tiny mono">${escapeHtml(String(e))}</p></div>`;
    return;
  }

  const sys = payload.system;
  document.getElementById("sysName").textContent = sys.name;
  document.getElementById("sysSubtitle").textContent = sys.subtitle;
  document.getElementById("sysTransport").textContent = `${sys.transport} · ${sys.model} · ${sys.tensor}`;

  renderGlossary(payload.glossary);
  bindNavButtons();
  bindHintButtons();
  applyDataset();
}

init();
