const form = document.getElementById("submit_request_form");
const addrInput = document.getElementById("addr");
const addrError = document.getElementById("addr-error");
const step1Card = document.getElementById("step1-card");
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
const parsedOutputSection = document.getElementById("parsed-output-section");
const parsedOutputCode = document.getElementById("parsed-output-code");
const copyParsedBtn = document.getElementById("copy-parsed-btn");
const pubInputSection = document.getElementById("pub-input-section");
const pubInputCode = document.getElementById("pub-input-code");
const copyPubInputBtn = document.getElementById("copy-pub-input-btn");
const txExplorerLink = document.getElementById("tx-explorer-link");
const submitTxBtn = document.getElementById("submit-tx-btn");
const themeToggle = document.getElementById("theme-toggle");
const themeToggleLabel = document.getElementById("theme-toggle-label");

const POLL_INTERVAL_MS = 3000;
const DEFAULT_AVG_PROCESSING_SEC = 10;
const MAX_PROGRESS_PCT = 95;
const PROCESSING_TIME_FUDGE = 2;
const SCROLL_DELAY_MS = 400;
const COPY_FEEDBACK_MS = 2000;

let pollTimer = null;
let activePollRequestId = null;

function setVisible(element, isVisible, displayValue = "block") {
  element.style.display = isVisible ? displayValue : "none";
}

function setButtonLoading(button, isLoading) {
  button.classList.toggle("is-loading", isLoading);
  button.disabled = isLoading;
}

function scrollIntoViewSoon(element, block = "nearest") {
  setTimeout(() => element.scrollIntoView({ behavior: "smooth", block }), SCROLL_DELAY_MS);
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

  const levels = [
    QRCode.CorrectLevel.M,
    QRCode.CorrectLevel.L,
    QRCode.CorrectLevel.Q,
    QRCode.CorrectLevel.H,
  ];

  for (const correctLevel of levels) {
    try {
      new QRCode(qrDiv, {
        text: url,
        width: 280,
        height: 280,
        colorDark: "#081B3A",
        colorLight: "#FFFFFF",
        correctLevel,
      });
      return;
    } catch (error) {
      qrDiv.innerHTML = "";
      if (
        !(error instanceof Error) ||
        !error.message.includes("code length overflow")
      ) {
        throw error;
      }
    }
  }

  qrDiv.innerHTML = `
    <p class="qr-fallback-message">
      QR code unavailable for this request size. Use the wallet link below.
    </p>
  `;
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
  themeToggle.setAttribute(
    "aria-pressed",
    theme === "light" ? "true" : "false",
  );
  themeToggle.setAttribute("aria-label", `Switch to ${nextTheme} mode`);
  themeToggleLabel.textContent =
    nextTheme === "light" ? "Light mode" : "Dark mode";
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

  setVisible(step1Card, true);
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
  parsedOutputCode.textContent = "";
  copyParsedBtn.textContent = "Copy";
  setVisible(parsedOutputSection, false);
  pubInputCode.textContent = "";
  copyPubInputBtn.textContent = "Copy JSON";
  setVisible(pubInputSection, false);
  resetTxAction();
}

function showQueueError(message) {
  setVisible(queueStatusDiv, true);
  setVisible(proofResultDiv, false);
  setQueueState("error", "Error");
  queueEtaEl.textContent = "";
  queueErrorEl.textContent = message || "Proof generation failed.";
  setVisible(queueErrorEl, true);
}

function applyQueueUpdate(status, data = {}) {
  const { queue_pos, queue_len, eta_seconds, proof, pub_input, parsed, tx_hash, tx_cbor } = data;

  if (status === "queued" || status === "processing") {
    setVisible(queueStatusDiv, true);
    setVisible(proofResultDiv, false);
    clearQueueError();

    if (queue_pos != null) queuePosEl.textContent = queue_pos;
    if (queue_len != null) queueTotalEl.textContent = queue_len;

    if (status === "processing") {
      queueEtaEl.textContent = "Processing...";
      setQueueState("processing", "Processing");
    } else if (eta_seconds != null) {
      queueEtaEl.textContent =
        eta_seconds >= 60
          ? `~${Math.ceil(eta_seconds / 60)} min remaining`
          : `~${eta_seconds}s remaining`;
      setQueueState("queued", "Queued");
    } else {
      queueEtaEl.textContent = "";
      setQueueState("queued", "Queued");
    }
    return;
  }

  if (status === "success") {
    setVisible(queueStatusDiv, false);
    setVisible(proofResultDiv, true);
    scrollIntoViewSoon(proofResultDiv);
    setQueueState("complete", "Complete");

    // Display human-readable parsed output first (most important for users)
    if (parsed) {
      // Handle ParsedPubInput struct: {value: "actual content"}
      let displayContent;
      if (parsed.value !== undefined) {
        // Extract the value field from ParsedPubInput struct
        displayContent = parsed.value;
      } else if (typeof parsed === 'string') {
        // Fallback for simple string
        displayContent = parsed;
      } else {
        // Fallback for other object types
        displayContent = JSON.stringify(parsed, null, 2);
      }
      
      parsedOutputCode.textContent = displayContent;
      setVisible(parsedOutputSection, true);
    } else {
      setVisible(parsedOutputSection, false);
    }

    // Display technical proof data
    proofJsonCode.textContent = proof ? JSON.stringify(proof, null, 2) : "";

    // Display raw public input (for developers/verification)
    if (pub_input) {
      pubInputCode.textContent = JSON.stringify(pub_input, null, 2);
      setVisible(pubInputSection, true);
    } else {
      setVisible(pubInputSection, false);
    }

    updateTxLink(tx_hash);

    if (tx_cbor) {
      submitTxBtn.dataset.cbor = tx_cbor;
      setVisible(submitTxBtn, true, "inline-flex");
    }
    return;
  }

  if (status === "error") {
    // Handle UserError which can be a string or object
    let errorMessage = "Proof generation failed.";
    if (typeof data === 'string') {
      errorMessage = data;
    } else if (data && data.message) {
      errorMessage = data.message;
    } else if (data && data.error) {
      errorMessage = data.error;
    } else if (data && typeof data === 'object') {
      errorMessage = JSON.stringify(data);
    }
    showQueueError(errorMessage);
  }
}

function startProofPolling(requestId) {
  stopProofPolling();
  activePollRequestId = requestId;

  const statusUrl = `/api/status/${requestId}`;

  let jobStatus = null;
  let startTime = null;
  const avgProcessingTime = DEFAULT_AVG_PROCESSING_SEC;

  const showStep3 = () => {
    setVisible(outputDiv, false);
    setVisible(step1Card, false);
    setVisible(step3Div, true);
    scrollIntoViewSoon(step3Div);
  };

  const updateProgress = () => {
    if (!startTime || jobStatus === "completed" || jobStatus === "error") {
      return;
    }

    const elapsed = (Date.now() - startTime) / 1000;
    const expectedTime = avgProcessingTime * PROCESSING_TIME_FUDGE;

    if (jobStatus === "processing") {
      const pct = Math.min(MAX_PROGRESS_PCT, (elapsed / expectedTime) * 100);
      setQueueProgress(pct);
    } else if (jobStatus === "queued") {
      setQueueProgress(0);
    }
  };

  const pollStatus = async () => {
    try {
      const res = await fetch(statusUrl);
      if (!res.ok || activePollRequestId !== requestId) return;

      const data = await res.json();
      if (activePollRequestId !== requestId) return;

      const { status } = data;

      if (status === "waitingforvp") {
        setQueueState("queued", "Waiting for credential...");
        queuePosEl.textContent = "-";
        queueTotalEl.textContent = "-";
        queueEtaEl.textContent = "";
        setQueueProgress(0);
        jobStatus = null;
        startTime = null;
        return;
      }

      showStep3();

      // Handle different status types based on new API structure
      if (status === "queued") {
        const { pos, len } = data;
        const newStatus = "queued";
        if (jobStatus !== newStatus) {
          jobStatus = newStatus;
          startTime = Date.now();
        }

        let etaSeconds = null;
        if (pos != null && avgProcessingTime) {
          etaSeconds = pos * avgProcessingTime;
        }

        applyQueueUpdate(newStatus, {
          queue_pos: pos != null ? String(pos) : "-",
          queue_len: len,
          eta_seconds: etaSeconds,
        });
      } else if (status === "success") {
        const { proof, pub_input, parsed } = data;
        jobStatus = "success";
        
        applyQueueUpdate("success", {
          proof,
          pub_input,
          parsed,
          // tx_hash and tx_cbor would be included if the API provides them
        });
        
        stopProofPolling();
      } else if (status === "error") {
        jobStatus = "error";
        
        // The error data is directly in the response for UserError
        applyQueueUpdate("error", data);
        
        stopProofPolling();
      }
    } catch (err) {
      console.error("Polling error:", err);
    }
  };

  pollTimer = setInterval(async () => {
    updateProgress();
    await pollStatus();
  }, POLL_INTERVAL_MS);
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

      const res = await response.json();
      setVisible(outputDiv, true);
      scrollIntoViewSoon(outputDiv, "start");

      openidLink.href = res.url;
      renderQrCode(res.url);

      startProofPolling(res.id);
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

    navigator.clipboard
      .writeText(proofText)
      .then(() => {
        copyProofBtn.textContent = "Copied!";
        setTimeout(() => {
          copyProofBtn.textContent = "Copy JSON";
        }, COPY_FEEDBACK_MS);
      })
      .catch((err) => {
        console.error("Clipboard write failed:", err);
        alert(
          "Copy failed. Your browser may block clipboard access in this context.",
        );
      });
  });
}

function initializeCopyParsed() {
  copyParsedBtn.addEventListener("click", () => {
    const parsedText = parsedOutputCode.textContent;
    if (!parsedText) return;

    navigator.clipboard
      .writeText(parsedText)
      .then(() => {
        copyParsedBtn.textContent = "Copied!";
        setTimeout(() => {
          copyParsedBtn.textContent = "Copy";
        }, COPY_FEEDBACK_MS);
      })
      .catch((err) => {
        console.error("Clipboard write failed:", err);
        alert(
          "Copy failed. Your browser may block clipboard access in this context.",
        );
      });
  });
}

function initializeCopyPubInput() {
  copyPubInputBtn.addEventListener("click", () => {
    const pubInputText = pubInputCode.textContent;
    if (!pubInputText) return;

    navigator.clipboard
      .writeText(pubInputText)
      .then(() => {
        copyPubInputBtn.textContent = "Copied!";
        setTimeout(() => {
          copyPubInputBtn.textContent = "Copy JSON";
        }, COPY_FEEDBACK_MS);
      })
      .catch((err) => {
        console.error("Clipboard write failed:", err);
        alert(
          "Copy failed. Your browser may block clipboard access in this context.",
        );
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
initializeCopyParsed();
initializeCopyPubInput();
initializeSubmitTx();
