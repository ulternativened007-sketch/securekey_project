const $ = (id) => document.getElementById(id);

async function postJSON(path, data) {
  const response = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Something went wrong.");
  return result;
}

$("toggle").addEventListener("click", () => {
  const field = $("password");
  field.type = field.type === "password" ? "text" : "password";
});

function renderList(element, items) {
  element.replaceChildren();
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    element.appendChild(li);
  });
}

$("check-password").addEventListener("click", async () => {
  const password = $("password").value;
  try {
    const result = await postJSON("/api/password", {password});
    $("score").textContent = password ? `${result.score}/6` : "—";
    $("strength-label").textContent = result.label;
    $("strength-note").textContent = password ? "Estimate based on common password rules." : "Enter a password to begin.";
    $("strength-label").className = result.color;
    renderList($("tips"), result.tips);
  } catch (error) {
    $("strength-label").textContent = error.message;
  }
});

$("length").addEventListener("input", () => {
  $("length-value").textContent = $("length").value;
});

$("generate-button").addEventListener("click", async () => {
  try {
    const result = await postJSON("/api/generate", {
      length: Number($("length").value),
      upper: $("upper").checked,
      lower: $("lower").checked,
      digits: $("digits").checked,
      symbols: $("symbols").checked
    });
    $("generated-password").value = result.password;
    $("generate-status").textContent = `Strength estimate: ${result.strength.label}`;
    $("generate-status").className = `small-status ${result.strength.color}`;
  } catch (error) {
    $("generate-status").textContent = error.message;
    $("generate-status").className = "small-status bad";
  }
});

$("copy").addEventListener("click", async () => {
  const value = $("generated-password").value;
  if (!value) {
    $("generate-status").textContent = "Generate a password first.";
    return;
  }
  try {
    await navigator.clipboard.writeText(value);
    $("generate-status").textContent = "Copied to clipboard.";
  } catch {
    $("generated-password").select();
    $("generate-status").textContent = "Select and copy the password manually.";
  }
});

$("check-url").addEventListener("click", async () => {
  try {
    const result = await postJSON("/api/url", {url: $("url").value});
    $("url-label").textContent = result.label;
    $("url-label").className = result.color;
    $("url-icon").textContent = result.color === "good" ? "✓" : result.color === "bad" ? "!" : "?";
    $("url-host").textContent = result.host ? `Domain: ${result.host}` : "Check the address and try again.";
    renderList($("url-reasons"), result.reasons);
  } catch (error) {
    $("url-label").textContent = error.message;
  }
});
