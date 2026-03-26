/**
 * app.js — UI logic for the UDVS protocol demo.
 *
 * Imports the pure-crypto module (js/udvs.js) and wires the
 * step-by-step interactive protocol to the HTML.
 */

import {
  P, Q, G,
  genKeyPair,
  udvsSign,
  udvsVerify,
  udvsSimulate,
} from './udvs.js';

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

const state = {
  aliceKey : null,   // { x, y }
  bobKey   : null,
  sig      : null,   // UDVS from Alice
  simSig   : null,   // UDVS simulated by Bob
  step     : 0,
};

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

const $ = id => document.getElementById(id);

function setText(id, text) {
  const el = $(id);
  if (!el) return;
  el.textContent = String(text);
  el.classList.remove('fade-in');
  void el.offsetWidth;           // reflow to restart animation
  el.classList.add('fade-in');
}

function show(id)  { $(id)?.classList.remove('hidden'); }
function hide(id)  { $(id)?.classList.add('hidden'); }

function log(msg, type = 'info') {
  const container = $('log');
  if (!container) return;
  const palette = {
    info    : 'text-gray-300',
    alice   : 'text-blue-300',
    bob     : 'text-purple-300',
    success : 'text-green-400',
    error   : 'text-red-400',
    warn    : 'text-yellow-300',
    sep     : 'text-gray-500',
  };
  const timestamp = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  const line = document.createElement('div');
  line.className = palette[type] ?? 'text-gray-300';
  line.textContent = `[${timestamp}]  ${msg}`;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

function logSep(title) {
  log(`──── ${title} ────`, 'sep');
}

/** Append an animated message-arrow to the flow diagram. */
function addArrow(label, direction = 'right', colorClass = 'bg-green-600') {
  const wrap = $('flow-messages');
  if (!wrap) return;
  const div = document.createElement('div');
  div.className = 'flow-msg flex items-center gap-3 py-1';
  const arrowChar = direction === 'right' ? '→' : '←';
  div.innerHTML = `
    <span class="text-gray-500 text-xs w-10 text-right">${direction === 'right' ? 'Alice' : 'Bob'}</span>
    <span class="text-gray-400 text-lg font-bold">${arrowChar}</span>
    <span class="px-3 py-1 ${colorClass} text-white text-xs rounded-full shadow">${label}</span>
    <span class="text-gray-500 text-xs">${direction === 'right' ? 'Bob' : 'Alice'}</span>
  `;
  wrap.appendChild(div);
}

function markStepDone(n) {
  const badge  = $(`step${n}-badge`);
  const status = $(`step${n}-status`);
  if (badge)  { badge.textContent = '✓'; badge.className = 'w-7 h-7 rounded-full bg-green-500 flex items-center justify-center text-white text-sm font-bold flex-shrink-0'; }
  if (status) { status.textContent = '已完成'; status.className = 'text-xs font-medium text-green-400'; }
}

function markStepRunning(n) {
  const badge  = $(`step${n}-badge`);
  const status = $(`step${n}-status`);
  if (badge)  { badge.className = 'w-7 h-7 rounded-full bg-yellow-500 flex items-center justify-center text-white text-sm font-bold flex-shrink-0 animate-pulse'; }
  if (status) { status.textContent = '执行中…'; status.className = 'text-xs font-medium text-yellow-300 animate-pulse'; }
}

function enableBtn(id) { $(id)?.removeAttribute('disabled'); }
function disableBtn(id) { $(id)?.setAttribute('disabled', ''); }

// ---------------------------------------------------------------------------
// Step 1 — Key Generation
// ---------------------------------------------------------------------------

async function stepKeygen() {
  markStepRunning(1);
  logSep('步骤 1：密钥生成');

  setText('param-p', P.toString());
  setText('param-q', Q.toString());
  setText('param-g', G.toString());

  state.aliceKey = genKeyPair();
  log(`Alice 随机选取私钥  x_a = ${state.aliceKey.x}`, 'alice');
  log(`Alice 计算公钥      y_a = g^x_a mod p = ${state.aliceKey.y}`, 'alice');
  setText('alice-sk', state.aliceKey.x.toString());
  setText('alice-pk', state.aliceKey.y.toString());

  state.bobKey = genKeyPair();
  log(`Bob   随机选取私钥  x_b = ${state.bobKey.x}`, 'bob');
  log(`Bob   计算公钥      y_b = g^x_b mod p = ${state.bobKey.y}`, 'bob');
  setText('bob-sk', state.bobKey.x.toString());
  setText('bob-pk', state.bobKey.y.toString());

  // Exchange public keys
  show('flow-section');
  $('flow-messages').innerHTML = '';
  addArrow('pk_a (公钥)', 'right',  'bg-blue-600');
  addArrow('pk_b (公钥)', 'left',   'bg-purple-600');

  markStepDone(1);
  enableBtn('btn-sign');
  state.step = 1;
}

// ---------------------------------------------------------------------------
// Step 2 — UDVS Sign
// ---------------------------------------------------------------------------

async function stepSign() {
  if (!state.aliceKey) return;
  const message = $('msg-input').value.trim();
  if (!message) { showToast('请先输入要签名的消息！'); return; }

  markStepRunning(2);
  logSep('步骤 2：Alice 创建 UDVS');
  log(`消息  m = "${message}"`, 'info');

  state.sig = await udvsSign(message, state.aliceKey.x, state.aliceKey.y, state.bobKey.y);
  const s = state.sig;

  log('— 模拟 Bob 分支 (Alice 不知道 x_b) —', 'alice');
  log(`  随机选取模拟参数  c_b = ${s.c_b},  s_b = ${s.s_b}`, 'alice');
  log(`  T_b = g^s_b · y_b^c_b mod p  =  ${s.T_b}`, 'alice');

  log('— Alice 真实分支承诺 —', 'alice');
  log(`  随机选取 r_a,  T_a = g^r_a mod p  =  ${s.T_a}`, 'alice');

  log('— Fiat-Shamir 挑战 —', 'alice');
  log(`  c = H(m ‖ T_a ‖ T_b ‖ y_a ‖ y_b)  mod q`, 'alice');
  log(`  分割挑战：c_a = c − c_b mod q  =  ${s.c_a}`, 'alice');
  log(`  Schnorr 响应：s_a = r_a − x_a·c_a mod q  =  ${s.s_a}`, 'alice');
  log(`签名 σ' = (T_a, T_b, c_a, s_a, c_b, s_b)`, 'success');

  // Update Alice panel
  setText('sig-T_a', s.T_a.toString());
  setText('sig-c_a', s.c_a.toString());
  setText('sig-s_a', s.s_a.toString());
  show('alice-sig-panel');

  // Update Bob panel (receives the signature)
  setText('recv-T_b', s.T_b.toString());
  setText('recv-c_b', s.c_b.toString());
  setText('recv-s_b', s.s_b.toString());
  show('bob-recv-panel');

  // Arrow
  addArrow("σ' (UDVS 签名)", 'right', 'bg-green-600');

  markStepDone(2);
  enableBtn('btn-verify');
  state.step = 2;
}

// ---------------------------------------------------------------------------
// Step 3 — UDVS Verify
// ---------------------------------------------------------------------------

async function stepVerify() {
  if (!state.sig) return;
  const message = $('msg-input').value.trim();

  markStepRunning(3);
  logSep('步骤 3：Bob 验证 UDVS');

  const r = await udvsVerify(message, state.sig, state.aliceKey.y, state.bobKey.y);
  const s = state.sig;

  log(`(1) Alice 分支：T_a ?= g^s_a · y_a^c_a mod p`, 'bob');
  log(`     期望 T_a = ${r.T_a_exp}`, 'bob');
  log(`     实际 T_a = ${s.T_a}  →  ${r.Ta_ok ? '✅ 一致' : '❌ 不一致'}`, r.Ta_ok ? 'success' : 'error');

  log(`(2) Bob  分支：T_b ?= g^s_b · y_b^c_b mod p`, 'bob');
  log(`     期望 T_b = ${r.T_b_exp}`, 'bob');
  log(`     实际 T_b = ${s.T_b}  →  ${r.Tb_ok ? '✅ 一致' : '❌ 不一致'}`, r.Tb_ok ? 'success' : 'error');

  log(`(3) 挑战一致性：c_a + c_b ?= H(m‖…) mod q`, 'bob');
  log(`     c_a + c_b = ${r.c_sum}`, 'bob');
  log(`     H(…)      = ${r.c_exp}  →  ${r.c_ok ? '✅ 一致' : '❌ 不一致'}`, r.c_ok ? 'success' : 'error');

  if (r.valid) {
    log('✅  UDVS 验证通过！Bob 确认签名有效。', 'success');
  } else {
    log('❌  UDVS 验证失败！', 'error');
  }

  const badge = $('verify-badge');
  if (r.valid) {
    badge.className = 'mt-4 py-3 px-4 rounded-xl text-center font-bold text-lg bg-green-900 border-2 border-green-500 text-green-300 shadow-lg';
    badge.textContent = '✅ 验证成功';
  } else {
    badge.className = 'mt-4 py-3 px-4 rounded-xl text-center font-bold text-lg bg-red-900 border-2 border-red-500 text-red-300 shadow-lg';
    badge.textContent = '❌ 验证失败';
  }
  show('verify-badge');

  markStepDone(3);
  enableBtn('btn-simulate');
  state.step = 3;
}

// ---------------------------------------------------------------------------
// Step 4 — Non-Transferability (Bob simulates)
// ---------------------------------------------------------------------------

async function stepSimulate() {
  if (!state.sig) return;
  const message = $('msg-input').value.trim();

  markStepRunning(4);
  logSep('步骤 4：不可转移性演示');
  log('Bob 使用自己的私钥 x_b 独立模拟一份有效的 UDVS…', 'bob');

  state.simSig = await udvsSimulate(message, state.bobKey.x, state.aliceKey.y, state.bobKey.y);
  const bs = state.simSig;

  log('— 模拟 Alice 分支 (Bob 不知道 x_a) —', 'bob');
  log(`  T_a_sim = g^s_a · y_a^c_a mod p  =  ${bs.T_a}`, 'bob');
  log('— Bob 真实分支承诺 —', 'bob');
  log(`  T_b_sim = g^r_b mod p  =  ${bs.T_b}`, 'bob');
  log(`  Schnorr 响应：s_b = r_b − x_b·c_b mod q  =  ${bs.s_b}`, 'bob');

  const simR = await udvsVerify(message, state.simSig, state.aliceKey.y, state.bobKey.y);
  log(`Bob 模拟签名验证结果：${simR.valid ? '✅ 有效' : '❌ 无效'}`, simR.valid ? 'success' : 'error');

  // Populate comparison table
  const orig = state.sig;
  $('cmp-alice-T_a').textContent = orig.T_a.toString();
  $('cmp-alice-T_b').textContent = orig.T_b.toString();
  $('cmp-alice-c_a').textContent = orig.c_a.toString();
  $('cmp-alice-s_a').textContent = orig.s_a.toString();
  $('cmp-alice-c_b').textContent = orig.c_b.toString();
  $('cmp-alice-s_b').textContent = orig.s_b.toString();
  $('cmp-alice-valid').textContent = '✅ 有效';
  $('cmp-alice-valid').className = 'text-green-400 font-bold';

  $('cmp-bob-T_a').textContent = bs.T_a.toString();
  $('cmp-bob-T_b').textContent = bs.T_b.toString();
  $('cmp-bob-c_a').textContent = bs.c_a.toString();
  $('cmp-bob-s_a').textContent = bs.s_a.toString();
  $('cmp-bob-c_b').textContent = bs.c_b.toString();
  $('cmp-bob-s_b').textContent = bs.s_b.toString();
  $('cmp-bob-valid').textContent = simR.valid ? '✅ 有效' : '❌ 无效';
  $('cmp-bob-valid').className = simR.valid ? 'text-green-400 font-bold' : 'text-red-400 font-bold';

  show('nontransfer-section');

  logSep('结论');
  log('两份签名都通过验证，第三方无法区分哪份来自 Alice、哪份来自 Bob。', 'warn');
  log('→ UDVS 不可转移性成立：Bob 无法向第三方证明是 Alice 生成了该签名。', 'success');

  markStepDone(4);
  state.step = 4;
}

// ---------------------------------------------------------------------------
// Reset
// ---------------------------------------------------------------------------

function resetAll() {
  Object.assign(state, { aliceKey: null, bobKey: null, sig: null, simSig: null, step: 0 });

  const placeholders = {
    'param-p': '—', 'param-q': '—', 'param-g': '—',
    'alice-sk': '未生成', 'alice-pk': '未生成',
    'bob-sk':   '未生成', 'bob-pk':   '未生成',
    'sig-T_a': '—', 'sig-c_a': '—', 'sig-s_a': '—',
    'recv-T_b': '—', 'recv-c_b': '—', 'recv-s_b': '—',
  };
  for (const [id, val] of Object.entries(placeholders)) {
    const el = $(id);
    if (el) { el.textContent = val; el.classList.remove('fade-in'); }
  }

  ['alice-sig-panel', 'bob-recv-panel', 'verify-badge', 'flow-section', 'nontransfer-section'].forEach(hide);
  $('flow-messages').innerHTML = '';
  $('log').innerHTML = '';

  // Reset step badges
  for (let n = 1; n <= 4; n++) {
    const badge  = $(`step${n}-badge`);
    const status = $(`step${n}-status`);
    if (badge)  { badge.textContent = n; badge.className = 'w-7 h-7 rounded-full bg-gray-600 flex items-center justify-center text-white text-sm font-bold flex-shrink-0'; }
    if (status) { status.textContent = '待执行'; status.className = 'text-xs font-medium text-gray-400'; }
  }

  disableBtn('btn-sign');
  disableBtn('btn-verify');
  disableBtn('btn-simulate');

  log('已重置。请点击「密钥生成」开始新的协议演示。', 'info');
}

// ---------------------------------------------------------------------------
// Toast helper
// ---------------------------------------------------------------------------

function showToast(msg) {
  let toast = $('toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'toast';
    toast.className = 'fixed bottom-8 left-1/2 -translate-x-1/2 bg-red-700 text-white px-6 py-3 rounded-full shadow-xl z-50 text-sm font-medium transition-opacity duration-500';
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.style.opacity = '1';
  setTimeout(() => { toast.style.opacity = '0'; }, 2500);
}

// ---------------------------------------------------------------------------
// Wire up buttons & init
// ---------------------------------------------------------------------------

$('btn-keygen').addEventListener('click',   stepKeygen);
$('btn-sign').addEventListener('click',     stepSign);
$('btn-verify').addEventListener('click',   stepVerify);
$('btn-simulate').addEventListener('click', stepSimulate);
$('btn-reset').addEventListener('click',    resetAll);

log('UDVS 协议演示已就绪。点击「密钥生成」开始。', 'info');
