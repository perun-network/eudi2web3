const form = document.getElementById("submit_request_form");
const addrInput = document.getElementById("addr");
const addrError = document.getElementById("addr-error");
const outputDiv = document.getElementById("output");
const openidLink = document.getElementById("openid_link");
const qrDiv = document.getElementById("qr");
const submitBtn = document.getElementById("submit-btn");

const step3Div = document.getElementById("step3");
const queueStatusDiv = document.getElementById("queue-status");
const proofResultDiv = document.getElementById("proof-result");
const queuePosEl = document.getElementById("queue-pos");
const queueTotalEl = document.getElementById("queue-total");
const queueEtaEl = document.getElementById("queue-eta");
const queueProgressEl = document.getElementById("queue-progress-fill");
const queueTrackEl = document.getElementById("queue-progress-track");
const queueStateBadge = document.getElementById("queue-state-badge");
const queueStateText = document.getElementById("queue-state-text");
const queueErrorEl = document.getElementById("queue-error");
const proofJsonCode = document.getElementById("proof-json-code");
const copyProofBtn = document.getElementById("copy-proof-btn");
const txExplorerLink = document.getElementById("tx-explorer-link");
const submitTxBtn = document.getElementById("submit-tx-btn");
const themeToggle = document.getElementById("theme-toggle");
const themeToggleLabel = document.getElementById("theme-toggle-label");

let pollTimer = null;
let activePollRequestId = null;

function setVisible(element, isVisible, displayValue = "block") {
  element.style.display = isVisible ? displayValue : "none";
}

function setButtonLoading(button, isLoading) {
  button.classList.toggle("is-loading", isLoading);
  button.disabled = isLoading;
}

function scrollIntoViewSoon(element, block = "nearest", delay = 0) {
  const run = () => element.scrollIntoView({ behavior: "smooth", block });
  if (delay > 0) {
    setTimeout(run, delay);
    return;
  }

  run();
}

function setQueueState(state, label) {
  queueStateBadge.dataset.state = state;
  queueStateText.textContent = label;
}

function setQueueProgress(value) {
  queueProgressEl.style.width = `${value}%`;
  queueTrackEl.setAttribute("aria-valuenow", String(Math.round(value)));
}

function clearQueueError() {
  queueErrorEl.textContent = "";
  setVisible(queueErrorEl, false);
}

function resetTxAction() {
  txExplorerLink.href = "#";
  setVisible(txExplorerLink, false);

  delete submitTxBtn.dataset.cbor;
  setVisible(submitTxBtn, false);
  setButtonLoading(submitTxBtn, false);
}

function renderQrCode(url) {
  qrDiv.innerHTML = "";
  new QRCode(qrDiv, {
    text: url,
    width: 280,
    height: 280,
    colorDark: "#081B3A",
    colorLight: "#FFFFFF",
  });
}

function getRequestFailureMessage(error) {
  if (window.location.protocol === "file:") {
    return "Request failed. Open the page through the local web server, not via file://.";
  }

  if (error instanceof TypeError) {
    return "Request failed. The API is unreachable or not running at this site.";
  }

  return "Request failed. Please check your connection and try again.";
}

function getCurrentTheme() {
  return document.documentElement.getAttribute("data-theme") || "dark";
}

function syncThemeUi(theme) {
  const nextTheme = theme === "dark" ? "light" : "dark";
  themeToggle.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
  themeToggle.setAttribute("aria-label", `Switch to ${nextTheme} mode`);
  themeToggleLabel.textContent = nextTheme === "light" ? "Light mode" : "Dark mode";
}

function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
  syncThemeUi(theme);
}

function stopProofPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  activePollRequestId = null;
}

function setAddressError(message) {
  const hasError = Boolean(message);
  addrError.textContent = message || "";
  setVisible(addrError, hasError);
  addrInput.setAttribute("aria-invalid", hasError ? "true" : "false");
}

function isValidCardanoAddress(addr) {
  return /^(addr1|stake1)[0-9a-z]+$/i.test(addr);
}

function isSafeTxHash(txHash) {
  return /^[0-9a-f]{64}$/i.test(txHash);
}

function updateTxLink(txHash) {
  if (!isSafeTxHash(txHash)) {
    txExplorerLink.href = "#";
    setVisible(txExplorerLink, false);
    return;
  }

  txExplorerLink.href = `https://cardanoscan.io/transaction/${txHash}`;
  setVisible(txExplorerLink, true, "inline-flex");
}

function resetStepState() {
  stopProofPolling();

  setVisible(outputDiv, false);
  openidLink.href = "";
  qrDiv.innerHTML = "";

  setVisible(step3Div, false);
  setVisible(queueStatusDiv, true);
  setVisible(proofResultDiv, false);
  clearQueueError();

  queuePosEl.textContent = "-";
  queueTotalEl.textContent = "-";
  queueEtaEl.textContent = "";
  setQueueProgress(0);
  setQueueState("queued", "Queued");

  proofJsonCode.textContent = "";
  copyProofBtn.textContent = "Copy JSON";
  resetTxAction();
}

function extractRequestId(openidUrl) {
  try {
    const url = new URL(openidUrl);
    return url.searchParams.get("request_id")
      || url.searchParams.get("nonce")
      || url.searchParams.get("state")
      || url.searchParams.get("id");
  } catch {
    return null;
  }
}

function showQueueError(message) {
  setVisible(queueStatusDiv, true);
  setVisible(proofResultDiv, false);
  setQueueState("error", "Error");
  queueEtaEl.textContent = "";
  queueErrorEl.textContent = message || "Proof generation failed.";
  setVisible(queueErrorEl, true);
}

function applyQueueUpdate(data) {
  const { status, queue_position, queue_total, eta_seconds, proof, tx_hash, tx_cbor } = data;

  if (status === "queued" || status === "processing") {
    setVisible(queueStatusDiv, true);
    setVisible(proofResultDiv, false);
    clearQueueError();

    if (queue_position != null) queuePosEl.textContent = queue_position;
    if (queue_total != null) queueTotalEl.textContent = queue_total;

    if (queue_position != null && queue_total != null && queue_total > 0) {
      const pct = Math.max(4, Math.min(96, ((queue_total - queue_position) / queue_total) * 100));
      setQueueProgress(pct);
    }

    queueEtaEl.textContent = eta_seconds != null
      ? (eta_seconds >= 60 ? `~${Math.ceil(eta_seconds / 60)} min remaining` : `~${eta_seconds}s remaining`)
      : "";

    setQueueState(status, status === "processing" ? "Processing" : "Queued");
    return;
  }

  if (status === "complete") {
    setVisible(queueStatusDiv, false);
    setVisible(proofResultDiv, true);
    scrollIntoViewSoon(proofResultDiv);
    setQueueState("complete", "Complete");
    proofJsonCode.textContent = proof ? JSON.stringify(proof, null, 2) : "";

    updateTxLink(tx_hash);

    if (tx_cbor) {
      submitTxBtn.dataset.cbor = tx_cbor;
      setVisible(submitTxBtn, true, "inline-flex");
    }
    return;
  }

  if (status === "error") {
    showQueueError(data.message || data.error || "Proof generation failed.");
  }
}

function startProofPolling(openidUrl) {
  const requestId = extractRequestId(openidUrl);
  if (!requestId) {
    console.warn("Could not extract request ID - proof polling disabled.");
    return;
  }

  stopProofPolling();
  activePollRequestId = requestId;

  const statusUrl = `/api/proof-status/${encodeURIComponent(requestId)}`;

  setVisible(step3Div, true);
  scrollIntoViewSoon(step3Div, "nearest", 400);

  pollTimer = setInterval(async () => {
    try {
      const res = await fetch(statusUrl);
      if (!res.ok || activePollRequestId !== requestId) return;

      const data = await res.json();
      if (activePollRequestId !== requestId) return;

      applyQueueUpdate(data);
      if (data.status === "complete" || data.status === "error") {
        stopProofPolling();
      }
    } catch (err) {
      console.error("Polling error:", err);
    }
  }, 3000);
}

function initializeThemeToggle() {
  syncThemeUi(getCurrentTheme());

  themeToggle.addEventListener("click", () => {
    const nextTheme = getCurrentTheme() === "dark" ? "light" : "dark";
    setTheme(nextTheme);
  });
}

function initializeAddressValidation() {
  addrInput.addEventListener("input", () => {
    if (addrError.style.display !== "none") {
      setAddressError("");
    }
  });
}

function initializeProofRequest() {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const addr = form.addr.value.trim();
    form.addr.value = addr;
    setAddressError("");

    if (!addr) {
      setAddressError("Please enter a Cardano address.");
      addrInput.focus();
      return;
    }

    if (!isValidCardanoAddress(addr)) {
      setAddressError("Please enter a valid Cardano address.");
      addrInput.focus();
      return;
    }

    resetStepState();
    setButtonLoading(submitBtn, true);

    try {
      const response = await fetch(form.action, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ addr }),
      });

      if (!response.ok) {
        const text = await response.text();
        console.error("Server error:", response.status, text);
        alert(`Error: ${response.status}\n${text}`);
        return;
      }

      const url = await response.text();
      setVisible(outputDiv, true);
      scrollIntoViewSoon(outputDiv, "start");

      openidLink.href = url;
      renderQrCode(url);

      startProofPolling(url);
    } catch (err) {
      console.error("Request failed:", err);
      alert(getRequestFailureMessage(err));
    } finally {
      setButtonLoading(submitBtn, false);
    }
  });
}

function initializeCopyProof() {
  copyProofBtn.addEventListener("click", () => {
    const proofText = proofJsonCode.textContent;
    if (!proofText) return;

    navigator.clipboard.writeText(proofText).then(() => {
      copyProofBtn.textContent = "Copied!";
      setTimeout(() => {
        copyProofBtn.textContent = "Copy JSON";
      }, 2000);
    }).catch((err) => {
      console.error("Clipboard write failed:", err);
      alert("Copy failed. Your browser may block clipboard access in this context.");
    });
  });
}

function initializeSubmitTx() {
  submitTxBtn.addEventListener("click", async () => {
    setButtonLoading(submitTxBtn, true);

    try {
      const res = await fetch("/api/submit-tx", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tx_cbor: submitTxBtn.dataset.cbor }),
      });

      if (res.ok) {
        const { tx_hash } = await res.json();
        updateTxLink(tx_hash);
        setVisible(submitTxBtn, false);
      } else {
        const text = await res.text();
        alert(`Transaction failed: ${res.status}\n${text}`);
      }
    } catch (err) {
      console.error("Submit tx error:", err);
      alert("Transaction submission failed. Please try again.");
    } finally {
      setButtonLoading(submitTxBtn, false);
    }
  });
}

initializeThemeToggle();
initializeAddressValidation();
initializeProofRequest();
initializeCopyProof();
initializeSubmitTx();
