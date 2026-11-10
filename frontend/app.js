"use strict";

// The lab UI. One deliberate flaw lives here: in insecure mode the assistant's
// reply is rendered with innerHTML (see renderReply), which is the LLM05
// "insecure output handling" vulnerability made visible in the browser. Secure
// mode renders the same reply with textContent. Everything else uses textContent.

let current = null;          // selected challenge id
const solved = new Set();

async function loadChallenges() {
  const res = await fetch("/api/challenges");
  const challenges = await res.json();
  const list = document.getElementById("challenge-list");
  list.textContent = "";
  challenges.forEach((c) => {
    const li = document.createElement("li");
    li.dataset.id = c.id;
    const title = document.createElement("strong");
    title.textContent = c.title;                 // safe: textContent
    const tag = document.createElement("span");
    tag.className = "owasp";
    tag.textContent = c.owasp;
    li.append(tag, title);
    li.addEventListener("click", () => selectChallenge(c));
    list.appendChild(li);
  });
  if (challenges.length) selectChallenge(challenges[0]);
}

function selectChallenge(c) {
  current = c.id;
  document.querySelectorAll("#challenge-list li").forEach((li) =>
    li.classList.toggle("active", li.dataset.id === c.id));
  const detail = document.getElementById("challenge-detail");
  detail.textContent = "";
  const h = document.createElement("h2");
  h.textContent = `${c.owasp} — ${c.title}`;
  const desc = document.createElement("p");
  desc.textContent = c.description;
  const hint = document.createElement("details");
  const sum = document.createElement("summary");
  sum.textContent = "Hint";
  const hintBody = document.createElement("p");
  hintBody.textContent = c.hint;
  hint.append(sum, hintBody);
  detail.append(h, desc, hint);
  document.getElementById("transcript").textContent = "";
}

function currentMode() {
  return document.querySelector('input[name="mode"]:checked').value;
}

function renderReply(container, reply, mode) {
  const bubble = document.createElement("div");
  bubble.className = "bubble bot";
  if (mode === "insecure") {
    // VULNERABLE ON PURPOSE: model output rendered as HTML (LLM05).
    bubble.innerHTML = reply;
  } else {
    // FIX: model output treated as text.
    bubble.textContent = reply;
  }
  container.appendChild(bubble);
}

async function send(message) {
  const mode = currentMode();
  const transcript = document.getElementById("transcript");

  const you = document.createElement("div");
  you.className = "bubble you";
  you.textContent = message;                     // safe: textContent
  transcript.appendChild(you);

  let data;
  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: current, message, mode }),
    });
    data = await res.json();
  } catch (err) {
    const e = document.createElement("div");
    e.className = "bubble error";
    e.textContent = "Request failed: " + err;
    transcript.appendChild(e);
    return;
  }

  if (data.error) {
    const e = document.createElement("div");
    e.className = "bubble error";
    e.textContent = data.error;
    transcript.appendChild(e);
    return;
  }

  renderReply(transcript, data.reply, mode);

  if (data.solved) {
    solved.add(current);
    markSolved(current);
    const banner = document.createElement("div");
    banner.className = "solved";
    const flag = document.createElement("p");
    flag.textContent = `Solved in ${mode} mode — ${data.flag}`;
    const rc = document.createElement("p");
    rc.append(bold("Root cause: "), text(data.root_cause));
    const fix = document.createElement("p");
    fix.append(bold("Fix: "), text(data.fix));
    banner.append(flag, rc, fix);
    transcript.appendChild(banner);
  }
  transcript.scrollTop = transcript.scrollHeight;
}

function bold(t) { const b = document.createElement("strong"); b.textContent = t; return b; }
function text(t) { return document.createTextNode(t); }

function markSolved(id) {
  const li = document.querySelector(`#challenge-list li[data-id="${id}"]`);
  if (li && !li.querySelector(".tick")) {
    const tick = document.createElement("span");
    tick.className = "tick";
    tick.textContent = "✓";
    li.appendChild(tick);
  }
}

document.getElementById("chat-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const input = document.getElementById("message");
  const message = input.value.trim();
  if (message && current) {
    send(message);
    input.value = "";
  }
});

loadChallenges();
