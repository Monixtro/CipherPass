/* ===============================
   CipherPass – Checker Logic
   =============================== */

import {
  loadPasswordList,
  calculateEntropy,
  calculateScore,
  estimateCrackTimes
} from "./utils.js";

const passwordInput = document.getElementById("password");
const entropyText = document.getElementById("entropy");
const strengthFill = document.getElementById("strength-fill");

const crackOnline = document.getElementById("crack-online");
const crackGPU = document.getElementById("crack-gpu");
const crackBotnet = document.getElementById("crack-botnet");
const crackNation = document.getElementById("crack-nation");

/* Load leaked passwords once */
async function initChecker() {
  await loadPasswordList();

  passwordInput.addEventListener("input", () => {
    const password = passwordInput.value;

    const entropy = calculateEntropy(password);
    const score = calculateScore(entropy);
    const crackTimes = estimateCrackTimes(entropy, password);

    entropyText.textContent = entropy.toFixed(1) + " bits";

    strengthFill.style.width = score + "%";
    strengthFill.style.background =
      score < 40 ? "var(--danger)" :
      score < 70 ? "var(--warning)" :
      "var(--success)";

    crackOnline.textContent = crackTimes.online;
    crackGPU.textContent = crackTimes.gpu;
    crackBotnet.textContent = crackTimes.botnet;
    crackNation.textContent = crackTimes.nation;
  });
}

initChecker();