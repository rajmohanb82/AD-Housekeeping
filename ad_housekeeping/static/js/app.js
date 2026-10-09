(function () {
  const form = document.getElementById("scan-form");
  const steps = document.getElementById("steps");
  const status = document.getElementById("scan-status");
  if (form && steps) {
    form.addEventListener("submit", async function (event) {
      if (!window.fetch) return;
      event.preventDefault();
      const button = document.getElementById("scan-button");
      button.disabled = true;
      const items = Array.from(steps.querySelectorAll("li"));
      items.forEach((item) => item.classList.remove("done", "active"));
      status.textContent = "Reading the lab directory…";
      const body = new FormData(form);
      const response = await fetch(form.action, {
        method: "POST",
        headers: { "X-Requested-With": "fetch" },
        body,
      });
      const payload = await response.json();
      if (!response.ok || !payload.steps) {
        status.textContent = payload.error || "Sign in through the setup wizard first.";
        button.disabled = false;
        if (payload.redirect) window.location = payload.redirect;
        return;
      }
      for (let index = 0; index < items.length; index += 1) {
        items.forEach((item, itemIndex) => {
          item.classList.toggle("active", itemIndex === index);
          item.classList.toggle("done", itemIndex < index);
        });
        const step = payload.steps[index];
        status.textContent = step ? step.detail : "";
        await new Promise((resolve) => setTimeout(resolve, 450));
      }
      items.forEach((item) => {
        item.classList.remove("active");
        item.classList.add("done");
      });
      const summary = payload.summary;
      status.textContent = "Health " + summary.score + " · " + summary.total + " findings. Opening the queue.";
      window.location = payload.redirect;
    });
  }

  const password = document.getElementById("password");
  const meter = document.getElementById("meter");
  if (password && meter) {
    password.addEventListener("input", function () {
      const value = password.value;
      const classes =
        (/[a-z]/.test(value) ? 1 : 0) +
        (/[A-Z]/.test(value) ? 1 : 0) +
        (/[0-9]/.test(value) ? 1 : 0) +
        (/[^A-Za-z0-9]/.test(value) ? 1 : 0);
      if (value.length === 0) {
        meter.textContent = "At least 14 characters, three character classes, not the person's name.";
        return;
      }
      meter.textContent =
        value.length +
        " characters · " +
        classes +
        " of 4 classes" +
        (value.length >= 14 && classes >= 3 ? " · length and variety look fine" : " · keep going");
    });
  }
})();
