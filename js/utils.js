/* ===============================
   CipherPass – Utility Functions
   =============================== */

let compromisedPasswords = new Set();

/* Load leaked password list */
export async function loadPasswordList() {
  const res = await fetch("data/common-passwords.txt");
  const text = await res.text();
  text.split("\n").forEach(pw => {
    const clean = pw.trim().toLowerCase();
    if (clean) compromisedPasswords.add(clean);
  });
}

/* Character set sizes */
const CHARSETS = {
  lower: 26,
  upper: 26,
  number: 10,
  symbol: 32
};

/* Common weak passwords (fallback demo list) */
const COMMON_PASSWORDS = [
  "password",
  "123456",
  "12345678",
  "qwerty",
  "letmein",
  "admin",
  "welcome",
  "iloveyou"
];

const DICTIONARY_WORDS = [
  "password",
  "admin",
  "welcome",
  "dragon",
  "football",
  "monkey",
  "shadow",
  "master",
  "hello",
  "freedom",
  "troubador"
];


/* Detect repeated characters */
function hasRepeatedChars(password) {
  return /(.)\1{2,}/.test(password);
}

/* Detect sequential patterns */
function hasSequentialPattern(password) {
  const sequences = [
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789"
  ];

  const lower = password.toLowerCase();

  for (let seq of sequences) {
    for (let i = 0; i < seq.length - 3; i++) {
      if (lower.includes(seq.substring(i, i + 4))) {
        return true;
      }
    }
  }
  return false;
}

/* Detect keyboard patterns */
function hasKeyboardPattern(password) {
  const patterns = ["qwerty", "asdf", "zxcv"];
  const lower = password.toLowerCase();
  return patterns.some(p => lower.includes(p));
}

/* Normalize leetspeak */
function normalizePassword(password) {
  return password
    .toLowerCase()
    .replace(/@/g, "a")
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/\$/g, "s")
    .replace(/!/g, "i");
}

function extractBaseWord(password) {
  return password
    .toLowerCase()
    .replace(/[^a-z]/g, "");
}

/* Check if password is compromised */
export function isCompromised(password) {
  const lower = password.toLowerCase();

  // Exact match
  if (compromisedPasswords.has(lower)) return true;
  if (COMMON_PASSWORDS.includes(lower)) return true;

  // Base word BEFORE normalization
  const base = extractBaseWord(lower);

  if (base.length >= 4) {
    if (compromisedPasswords.has(base)) return true;
    if (COMMON_PASSWORDS.includes(base)) return true;
  }

  // Normalized (leet) full password
  const normalized = normalizePassword(lower);

  if (compromisedPasswords.has(normalized)) return true;
  if (COMMON_PASSWORDS.includes(normalized)) return true;

  return false;
}

/* Detect which character sets are used */
function detectCharsets(password) {
  return {
    lower: /[a-z]/.test(password),
    upper: /[A-Z]/.test(password),
    number: /[0-9]/.test(password),
    symbol: /[^A-Za-z0-9]/.test(password)
  };
}

function isLikelyPassphrase(password) {
  return /^[a-z]+$/.test(password) && password.length >= 16;
}

/* Calculate character pool size */
function getCharsetPoolSize(sets) {
  let pool = 0;
  if (sets.lower) pool += CHARSETS.lower;
  if (sets.upper) pool += CHARSETS.upper;
  if (sets.number) pool += CHARSETS.number;
  if (sets.symbol) pool += CHARSETS.symbol;
  return pool;
}

/* Entropy calculation */
export function calculateEntropy(password) {
  if (!password) return 0;

  const sets = detectCharsets(password);
  const poolSize = getCharsetPoolSize(sets);
  if (poolSize === 0) return 0;

  let entropy = password.length * Math.log2(poolSize);

  const normalized = normalizePassword(password);
  const base = extractBaseWord(password);
  const normalizedBase = extractBaseWord(normalizePassword(password));

  if (COMMON_PASSWORDS.includes(normalized)) entropy -= 30;
  if (hasRepeatedChars(password)) entropy -= 15;
  if (hasSequentialPattern(password)) entropy -= 15;
  if (hasKeyboardPattern(password)) entropy -= 15;

  // Dictionary word penalty
  if (
    base.length >= 4 &&
    (DICTIONARY_WORDS.includes(base) ||
     DICTIONARY_WORDS.includes(normalizedBase))
  ) {
    entropy -= 45;
  }

  // 🔥 Passphrase structural penalty (THIS WAS NEVER RUNNING)
  if (isLikelyPassphrase(password)) {
    entropy -= 50;
  }

  return Math.max(entropy, 0);
}


/* Crack models */
const ATTACK_MODELS = {
  online: 100,
  gpu: 1e9,
  botnet: 1e11,
  nation: 1e13
};

/* Crack time estimation */
export function estimateCrackTimes(entropy, password) {
  if (isCompromised(password)) {
    return {
      online: "Instant (known password)",
      gpu: "Instant",
      botnet: "Instant",
      nation: "Instant"
    };
  }

  const combinations = Math.pow(2, entropy);
  const results = {};

  for (const model in ATTACK_MODELS) {
    const seconds = combinations / ATTACK_MODELS[model];
    results[model] = formatTime(seconds);
  }

  return results;
}

/* Format seconds */
function formatTime(seconds) {
  if (!isFinite(seconds) || seconds <= 0) return "Instant";
  if (seconds > 1e18) return "Effectively impossible";

  const units = [
    { label: "second", value: 1 },
    { label: "minute", value: 60 },
    { label: "hour", value: 3600 },
    { label: "day", value: 86400 },
    { label: "month", value: 2592000 },
    { label: "year", value: 31536000 },
    { label: "millennium", value: 31536000000 }
  ];

  for (let i = units.length - 1; i >= 0; i--) {
    const amount = Math.floor(seconds / units[i].value);
    if (amount >= 1) {
      return `${amount} ${units[i].label}${amount > 1 ? "s" : ""}`;
    }
  }

  return "Instant";
}

/* Strength score */
export function calculateScore(entropy) {
  if (entropy >= 100) return 100;
  if (entropy <= 0) return 0;
  return Math.round(entropy);
}