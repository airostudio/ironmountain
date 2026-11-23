import { isCode, lineRule, type Rule } from "./types.js";

const SECURITY_CONTEXT = /(password|passwd|pwd|secret|token|nonce|salt|otp|session|csrf|api[_-]?key|reset|verification|auth|signature|key)/i;

export const cryptoRules: Rule[] = [
  lineRule({
    id: "crypto/weak-hash",
    title: "Weak hash algorithm (MD5/SHA-1)",
    severity: "medium",
    category: "crypto",
    confidence: "medium",
    cwe: ["CWE-327", "CWE-328"],
    description: "MD5 and SHA-1 are broken for collision resistance and must not protect passwords, signatures or integrity checks.",
    remediation: "Use SHA-256+ for integrity, and bcrypt/scrypt/Argon2id for passwords.",
    appliesTo: isCode,
    patterns: [
      /createHash\(\s*["'](md5|sha1)["']\s*\)/i,
      /\bhashlib\.(md5|sha1)\s*\((?![^)]*usedforsecurity\s*=\s*False)/,
      /\bMessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"\s*\)/i,
      /\b(md5|sha1)\.New\(\)/,
      /\bDigest::(MD5|SHA1)\b/,
      /\b(md5|sha1)\s*\(\s*\$/,
    ],
  }),
  lineRule({
    id: "crypto/password-plain-hash",
    title: "Password hashed with a fast hash",
    severity: "high",
    category: "crypto",
    confidence: "medium",
    cwe: ["CWE-916"],
    description: "General-purpose hashes (even SHA-256) are far too fast for password storage and are trivially brute-forced.",
    remediation: "Use a password KDF: Argon2id, scrypt, or bcrypt with a per-user salt.",
    appliesTo: isCode,
    patterns: [/(createHash|hashlib\.\w+|sha256|sha512|Sha256|SHA256)\s*\(?[^\n]*\bpassword\b/i],
    unless: [/bcrypt|argon2|scrypt|pbkdf2/i],
  }),
  lineRule({
    id: "crypto/insecure-random",
    title: "Non-cryptographic RNG used for security value",
    severity: "medium",
    category: "crypto",
    confidence: "medium",
    cwe: ["CWE-338"],
    description: "Math.random / random.* / rand() are predictable and must not generate tokens, passwords, salts or IDs used for access control.",
    remediation: "Use crypto.randomBytes / crypto.randomUUID (Node), secrets (Python), crypto/rand (Go), SecureRandom (Java/Ruby).",
    appliesTo: isCode,
    patterns: [
      /Math\.random\(\)/,
      /\brandom\.(random|randint|choice|choices|randrange|getrandbits|sample)\s*\(/,
      /\bmath\/rand\b|\brand\.(Intn|Int63|Read|Int)\(/,
      /\bnew\s+Random\s*\(/,
      /\b(mt_)?rand\s*\(\s*\)/,
    ],
    message: () => "Predictable RNG in a security-sensitive context.",
  }),
  lineRule({
    id: "crypto/broken-cipher",
    title: "Broken cipher or mode (DES, RC4, ECB, no-IV)",
    severity: "high",
    category: "crypto",
    confidence: "high",
    cwe: ["CWE-327"],
    description: "DES/3DES/RC4/Blowfish and ECB mode leak plaintext structure or are practically breakable; createCipher derives a key without IV.",
    remediation: "Use AES-256-GCM or ChaCha20-Poly1305 with a random nonce from a vetted library.",
    appliesTo: isCode,
    patterns: [
      /["'](des|des-ede3?|des3|rc4|rc2|bf|blowfish)(-[a-z0-9]+)?["']/i,
      /["']aes-\d{3}-ecb["']/i,
      /\bAES\.MODE_ECB\b|\bmodes\.ECB\(|Cipher\.getInstance\(\s*"AES(\/ECB[^"]*)?"\s*\)|"DES(ede)?\//i,
      /\bcrypto\.createCipher\s*\(/,
      /\bDES\.new\(|\bARC4\.new\(/,
    ],
  }),
  lineRule({
    id: "crypto/jwt-unverified",
    title: "JWT signature verification disabled",
    severity: "critical",
    category: "crypto",
    confidence: "high",
    cwe: ["CWE-347"],
    description: "Accepting unsigned/unverified JWTs lets anyone forge identities.",
    remediation: "Always verify signatures with an explicit allow-list of algorithms; never accept alg 'none'.",
    appliesTo: isCode,
    patterns: [
      /algorithms?\s*[:=]\s*\[?\s*["']none["']/i,
      /verify_signature["']?\s*:\s*False/,
      /\bjwt\.decode\([^)]*verify\s*=\s*False/,
      /\bjwt\.decode\s*\((?![^)]*(secret|key|algorithms))/,
      /ignoreExpiration\s*:\s*true/,
      /\.parseUnverified\(|\bParseUnverified\(/,
      /\bWithoutClaimsValidation\(\)|SkipClaimsValidation\s*:\s*true/,
    ],
  }),
  lineRule({
    id: "crypto/static-iv-or-salt",
    title: "Hardcoded IV, nonce, or salt",
    severity: "medium",
    category: "crypto",
    confidence: "low",
    cwe: ["CWE-329", "CWE-760"],
    description: "A constant IV/nonce/salt defeats the purpose of randomization and can enable key-stream reuse.",
    remediation: "Generate a fresh random IV/nonce per encryption and a unique salt per secret.",
    appliesTo: isCode,
    patterns: [/\b(iv|nonce|salt)\s*[:=]\s*(b?["'][^"']{6,}["']|Buffer\.from\(\s*["'])/i],
  }),
  lineRule({
    id: "crypto/timing-unsafe-compare",
    title: "Secret compared with a non-constant-time equality",
    severity: "low",
    category: "crypto",
    confidence: "low",
    cwe: ["CWE-208"],
    description: "Comparing signatures/tokens with == leaks timing information.",
    remediation: "Use crypto.timingSafeEqual / hmac.compare_digest / subtle.ConstantTimeCompare.",
    appliesTo: isCode,
    patterns: [/\b(signature|hmac|digest|token|api_?key|secret)\w*\s*(===?|!==?)\s*\w*(signature|hmac|digest|token|api_?key|secret|expected)/i],
    unless: [/(===?|!==?)\s*(null|undefined|None|""|''|0)\b/, /typeof|\.length/],
  }),
];

// Insecure RNG is only interesting near a security-sensitive identifier.
const rng = cryptoRules.find((r) => r.id === "crypto/insecure-random")!;
const rngCheck = rng.check.bind(rng);
rng.check = (ctx) => {
  const lines = new Map(ctx.file.added.map((l) => [l.line, l.content]));
  return rngCheck(ctx).filter((h) => {
    const window = [h.line - 1, h.line, h.line + 1].map((n) => lines.get(n) ?? "").join("\n");
    return SECURITY_CONTEXT.test(window);
  });
};
