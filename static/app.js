const fileInput = document.getElementById("binary_file");
const dropzone = document.getElementById("dropzone");
const filePill = document.getElementById("file-pill");

const MIN_PROCESSING_SCREEN_MS = 1800;
const COMPLETE_HOLD_MS = 700;

function applyVisualDataAttributes() {
  document.querySelectorAll("[data-bar-width]").forEach((element) => {
    const width = Number(element.getAttribute("data-bar-width") || 0);
    element.style.width = `${width}%`;
  });

  document.querySelectorAll("[data-score-angle]").forEach((element) => {
    const angle = Number(element.getAttribute("data-score-angle") || 0);
    element.style.setProperty("--score-angle", `${angle}deg`);
  });
}

function initUploadInput() {
  if (fileInput && filePill) {
    fileInput.addEventListener("change", () => {
      const file = fileInput.files && fileInput.files[0];
      filePill.textContent = file ? file.name : "No file selected";
    });
  }

  if (dropzone) {
    ["dragenter", "dragover"].forEach((eventName) => {
      dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.add("is-active");
      });
    });

    ["dragleave", "drop"].forEach((eventName) => {
      dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.remove("is-active");
      });
    });
  }
}

function initProcessingPage() {
  const root = document.getElementById("processing-root");
  if (!root) return;

  const taskId = root.getAttribute("data-task-id");
  const label = document.getElementById("processing-stage-label");
  const progressText = document.getElementById("processing-progress-text");
  const progressFill = document.getElementById("processing-progress-fill");
  const statusNote = document.getElementById("processing-status-note");

  if (!taskId) return;

  const pageStartedAt = Date.now();
  let lastProgress = 8;
  let redirectScheduled = false;

  function setProgress(progressValue) {
    const safeProgress = Math.max(
      lastProgress,
      Math.min(100, Number(progressValue) || 0),
    );
    lastProgress = safeProgress;

    if (progressText) progressText.textContent = `${safeProgress}%`;
    if (progressFill) progressFill.style.width = `${safeProgress}%`;
  }

  async function pollStatus() {
    try {
      const response = await fetch(`/task-status/${taskId}`, {
        method: "GET",
        headers: { Accept: "application/json" },
        cache: "no-store",
      });

      if (!response.ok) {
        if (statusNote) {
          statusNote.textContent = "Unable to fetch task status.";
        }
        window.setTimeout(pollStatus, 1200);
        return;
      }

      const data = await response.json();

      if (label) label.textContent = data.label || "Processing";
      setProgress(data.progress || 0);

      if (statusNote) {
        if (data.state === "failed") {
          statusNote.textContent = data.error || "Analysis failed.";
        } else {
          statusNote.textContent = `Current stage: ${data.label || "Processing"}`;
        }
      }

      if (data.state === "completed" && data.redirect_url) {
        if (redirectScheduled) return;
        redirectScheduled = true;

        const elapsed = Date.now() - pageStartedAt;
        const remainingMinTime = Math.max(
          0,
          MIN_PROCESSING_SCREEN_MS - elapsed,
        );

        if (label) label.textContent = "Finalizing result view";
        if (statusNote) statusNote.textContent = "Preparing analysis report…";

        window.setTimeout(() => {
          setProgress(100);

          window.setTimeout(() => {
            window.location.href = data.redirect_url;
          }, COMPLETE_HOLD_MS);
        }, remainingMinTime);

        return;
      }

      if (data.state === "failed") {
        return;
      }

      window.setTimeout(pollStatus, 900);
    } catch (_error) {
      if (statusNote) {
        statusNote.textContent = "Temporary connection issue. Retrying…";
      }
      window.setTimeout(pollStatus, 1500);
    }
  }

  pollStatus();
}

window.addEventListener("DOMContentLoaded", () => {
  applyVisualDataAttributes();
  initUploadInput();
  initProcessingPage();
});

window.addEventListener("pageshow", () => {
  applyVisualDataAttributes();
});
