import {
  calculateEntropy,
  estimateCrackTimes
} from "./utils.js";

const charsetMap = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{}<>?"
};

const lengthInput = document.getElementById("length");
const lengthValue = document.getElementById("length-value");
const output = document.getElementById("output");
const genEntropy = document.getElementById("gen-entropy");
const genCrack = document.getElementById("gen-crack");

lengthInput.addEventListener("input", () => {
  lengthValue.textContent = lengthInput.value;
});

document.getElementById("generate").addEventListener("click", () => {
  let charset = "";

  if (lower.checked) charset += charsetMap.lower;
  if (upper.checked) charset += charsetMap.upper;
  if (numbers.checked) charset += charsetMap.numbers;
  if (symbols.checked) charset += charsetMap.symbols;

  if (!charset) {
    alert("Select at least one character set");
    return;
  }

  let password = "";
  const cryptoObj = window.crypto || window.msCrypto;

  const randomValues = new Uint32Array(lengthInput.value);
  cryptoObj.getRandomValues(randomValues);

  for (let i = 0; i < randomValues.length; i++) {
    password += charset[randomValues[i] % charset.length];
  }

  output.value = password;

  const entropy = calculateEntropy(password);
  const crack = estimateCrackTimes(entropy, password);

  genEntropy.textContent = entropy.toFixed(1) + " bits";
  genCrack.textContent = crack.gpu;
});