/**
 * UDVS — Universal Designated Verifier Signature
 *
 * Construction: OR-proof (Cramer–Damgård–Schoenmakers 1994)
 *
 * The signer Alice proves, in zero-knowledge:
 *   "I know x_a  (s.t. y_a = g^x_a)  OR  I know x_b  (s.t. y_b = g^x_b)"
 * She uses her real key for the Alice branch and *simulates* the Bob branch.
 * Bob (knowing x_b) can do the opposite simulation, producing an
 * indistinguishable signature — hence the scheme is non-transferable.
 *
 * Group parameters (demo-sized, NOT production-secure):
 *   p = 1 000 000 007   (safe prime)
 *   q = 500 000 003     (Sophie-Germain prime,  p = 2q + 1)
 *   g = 100             (generator of order q mod p)
 *
 * WARNING: toy parameters chosen for readability. Use 2048-bit groups in production.
 */

'use strict';

// ---------------------------------------------------------------------------
// Group parameters
// ---------------------------------------------------------------------------

export const P = 1_000_000_007n;   // safe prime
export const Q = 500_000_003n;     // order of the subgroup
export const G = 100n;             // generator of order Q mod P

// ---------------------------------------------------------------------------
// Low-level BigInt helpers
// ---------------------------------------------------------------------------

/** Fast modular exponentiation (square-and-multiply). */
export function modpow(base, exp, mod) {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

/** Uniform random BigInt in [min, max). */
export function randomInRange(min, max) {
  const range = max - min;
  const byteLen = Math.ceil(range.toString(2).length / 8) + 1;
  let r;
  do {
    const buf = new Uint8Array(byteLen);
    crypto.getRandomValues(buf);
    r = buf.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n) % range;
  } while (r < 0n);
  return min + r;
}

/**
 * Hash several BigInt / string values to Z_q using SHA-256.
 * Arguments are joined with '||' before hashing.
 */
export async function H(...args) {
  const str = args.map(a => a.toString()).join('||');
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  let n = 0n;
  for (const b of new Uint8Array(buf)) n = (n << 8n) | BigInt(b);
  return n % Q;
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/** Generate a key-pair { x (private), y = g^x mod p (public) }. */
export function genKeyPair() {
  const x = randomInRange(2n, Q);
  const y = modpow(G, x, P);
  return { x, y };
}

// ---------------------------------------------------------------------------
// UDVS Sign  (Alice → Bob)
// ---------------------------------------------------------------------------

/**
 * Create a Designated-Verifier Signature on `message` from Alice (x_a, y_a)
 * designated to Bob (y_b).
 *
 * OR-proof structure:
 *   Alice proves  "y_a = g^x_a"  (real)  OR  "y_b = g^x_b"  (simulated)
 *
 * Returns { T_a, T_b, c_a, s_a, c_b, s_b }
 */
export async function udvsSign(message, x_a, y_a, y_b) {
  // ── Simulate Bob's branch (Alice does NOT know x_b) ──────────────────────
  const c_b = randomInRange(0n, Q);
  const s_b = randomInRange(0n, Q);
  // Choose T_b so that  g^s_b · y_b^c_b ≡ T_b  holds for any (c_b, s_b).
  const T_b = (modpow(G, s_b, P) * modpow(y_b, c_b, P)) % P;

  // ── Commit for Alice's real branch ────────────────────────────────────────
  const r_a = randomInRange(1n, Q);
  const T_a = modpow(G, r_a, P);   // T_a = g^r_a

  // ── Fiat-Shamir challenge ─────────────────────────────────────────────────
  const c = await H(message, T_a, T_b, y_a, y_b);

  // ── Alice's response  (c_a = c − c_b mod q) ──────────────────────────────
  const c_a = ((c - c_b) % Q + Q) % Q;
  const s_a = ((r_a - x_a * c_a) % Q + Q) % Q;   // s_a = r_a − x_a·c_a

  return { T_a, T_b, c_a, s_a, c_b, s_b };
}

// ---------------------------------------------------------------------------
// UDVS Verify
// ---------------------------------------------------------------------------

/**
 * Verify a Designated-Verifier Signature.
 *
 * Checks:
 *   (1) T_a ≡ g^s_a · y_a^c_a  (mod p)
 *   (2) T_b ≡ g^s_b · y_b^c_b  (mod p)
 *   (3) c_a + c_b ≡ H(m, T_a, T_b, y_a, y_b)  (mod q)
 *
 * Returns { valid, Ta_ok, Tb_ok, c_ok, T_a_exp, T_b_exp, c_exp, c_sum }
 */
export async function udvsVerify(message, sig, y_a, y_b) {
  const { T_a, T_b, c_a, s_a, c_b, s_b } = sig;

  const T_a_exp = (modpow(G, s_a, P) * modpow(y_a, c_a, P)) % P;
  const T_b_exp = (modpow(G, s_b, P) * modpow(y_b, c_b, P)) % P;

  const c_exp = await H(message, T_a, T_b, y_a, y_b);
  const c_sum = (c_a + c_b) % Q;

  const Ta_ok = T_a === T_a_exp;
  const Tb_ok = T_b === T_b_exp;
  const c_ok  = c_exp === c_sum;

  return { valid: Ta_ok && Tb_ok && c_ok, Ta_ok, Tb_ok, c_ok, T_a_exp, T_b_exp, c_exp, c_sum };
}

// ---------------------------------------------------------------------------
// UDVS Simulate  (Bob creates an indistinguishable signature himself)
// ---------------------------------------------------------------------------

/**
 * Bob simulates a valid DVS using only his own private key x_b.
 * The result is computationally indistinguishable from udvsSign output,
 * proving non-transferability: a third party cannot tell the difference.
 *
 * OR-proof structure:
 *   Bob proves  "y_b = g^x_b"  (real)  OR  "y_a = g^x_a"  (simulated)
 *
 * Returns { T_a, T_b, c_a, s_a, c_b, s_b }
 */
export async function udvsSimulate(message, x_b, y_a, y_b) {
  // ── Simulate Alice's branch (Bob does NOT know x_a) ───────────────────────
  const c_a = randomInRange(0n, Q);
  const s_a = randomInRange(0n, Q);
  const T_a = (modpow(G, s_a, P) * modpow(y_a, c_a, P)) % P;

  // ── Commit for Bob's real branch ──────────────────────────────────────────
  const r_b = randomInRange(1n, Q);
  const T_b = modpow(G, r_b, P);

  // ── Fiat-Shamir challenge ─────────────────────────────────────────────────
  const c = await H(message, T_a, T_b, y_a, y_b);

  // ── Bob's response  (c_b = c − c_a mod q) ────────────────────────────────
  const c_b = ((c - c_a) % Q + Q) % Q;
  const s_b = ((r_b - x_b * c_b) % Q + Q) % Q;

  return { T_a, T_b, c_a, s_a, c_b, s_b };
}
