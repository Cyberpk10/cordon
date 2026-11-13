/*
 * Cordon for Outlook: a thin client. It reads the open message, sends it to Cordon's
 * POST /v1/analyze/email, shows the verdict, and lets the user ask questions about it via
 * POST /v1/assistant. All detection and all assistant reasoning happen in the Cordon backend.
 *
 * Rendering rule: every string from the API (or from the email) is inserted with
 * textContent / createTextNode via el(). innerHTML is never used, so no API or LLM text can
 * become markup.
 *
 * The API key is stored in Office.context.roamingSettings (per user, per add-in).
 */
(function () {
  "use strict";

  // Local dev (Vite on localhost) proxies /v1 to the local backend; everything else uses prod.
  var API_BASE = /^(localhost|127\.0\.0\.1)$/.test(location.hostname)
    ? ""
    : "https://aegis-backend-zbcr.onrender.com";
  var KEY_SETTING = "cordonApiKey";
  var HISTORY_LIMIT = 20;
  var STARTERS = ["Is this phishing?", "Why did it get this rating?", "What should I do?", "Is the sender safe?"];

  var state = {
    raw: null, // raw RFC-822 text of the open message
    source: null, // "file" | "rest" | "assembled"
    itemId: null,
    analysis: null,
    history: [],
    busy: false,
    generation: 0, // bumps when the selected item changes; stale async results are dropped
  };

  var app = document.getElementById("app");
  var changeKeyBtn = document.getElementById("change-key");

  // ---- DOM helper (the only way text reaches the page) --------------------------------------

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function show(node) {
    while (app.firstChild) app.removeChild(app.firstChild);
    app.appendChild(node);
  }

  function messageCard(title, text, isError, actions) {
    var card = el("div", "card");
    card.appendChild(el("h2", isError ? "error" : "", title));
    card.appendChild(el("p", "", text));
    if (actions && actions.length) {
      var row = el("div", "row");
      actions.forEach(function (a) { row.appendChild(a); });
      card.appendChild(row);
    }
    return card;
  }

  function button(label, onClick, secondary) {
    var b = el("button", secondary ? "btn btn-secondary" : "btn", label);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }

  // ---- API key (roamingSettings) ------------------------------------------------------------

  function getKey() {
    try {
      return Office.context.roamingSettings.get(KEY_SETTING) || null;
    } catch (e) {
      return null;
    }
  }

  function saveKey(key, done) {
    var rs = Office.context.roamingSettings;
    rs.set(KEY_SETTING, key);
    rs.saveAsync(function (res) {
      done(res.status === Office.AsyncResultStatus.Succeeded);
    });
  }

  function showKeyCard(message, isError) {
    changeKeyBtn.hidden = true;
    var card = el("div", "card");
    card.appendChild(el("h2", "", "Connect Cordon"));
    card.appendChild(el("p", isError ? "error" : "muted", message));
    var input = el("input");
    input.type = "password";
    input.placeholder = "cdn_…";
    input.autocomplete = "off";
    input.setAttribute("aria-label", "Cordon API key");
    card.appendChild(input);
    var hint = el("p", "small muted", "Create a key in Cordon: Settings → API keys. It's stored in your Outlook settings, only for you.");
    card.appendChild(hint);
    var status = el("p", "small error");
    var saveBtn = button("Save key", function () {
      var key = input.value.trim();
      if (key.indexOf("cdn_") !== 0) {
        status.textContent = 'That doesn\'t look like a Cordon API key (it starts with "cdn_").';
        return;
      }
      saveBtn.disabled = true;
      saveKey(key, function (ok) {
        if (!ok) {
          saveBtn.disabled = false;
          status.textContent = "Outlook couldn't save the key. Try again.";
          return;
        }
        start();
      });
    });
    var row = el("div", "row");
    row.appendChild(saveBtn);
    card.appendChild(row);
    card.appendChild(status);
    show(card);
    input.focus();
  }

  // ---- reading the message ------------------------------------------------------------------

  function supports(version) {
    try {
      return Office.context.requirements.isSetSupported("Mailbox", version);
    } catch (e) {
      return false;
    }
  }

  function base64ToUtf8(b64) {
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
  }

  // (a) Mailbox 1.14: the message as Base64 EML. No token needed.
  function readAsFile() {
    return new Promise(function (resolve, reject) {
      var item = Office.context.mailbox.item;
      if (!supports("1.14") || typeof item.getAsFileAsync !== "function") {
        reject(new Error("getAsFileAsync not supported"));
        return;
      }
      item.getAsFileAsync(function (res) {
        if (res.status !== Office.AsyncResultStatus.Succeeded) {
          reject(new Error((res.error && res.error.message) || "getAsFileAsync failed"));
          return;
        }
        try {
          resolve(base64ToUtf8(res.value));
        } catch (e) {
          reject(e);
        }
      });
    });
  }

  // (b) REST callback token + $value. Exchange Online has retired these tokens; this still
  // works on on-premises Exchange.
  function readViaRest() {
    return new Promise(function (resolve, reject) {
      var mailbox = Office.context.mailbox;
      if (!mailbox.restUrl || typeof mailbox.getCallbackTokenAsync !== "function") {
        reject(new Error("REST not available"));
        return;
      }
      mailbox.getCallbackTokenAsync({ isRest: true }, function (res) {
        if (res.status !== Office.AsyncResultStatus.Succeeded) {
          reject(new Error((res.error && res.error.message) || "no callback token"));
          return;
        }
        var id = mailbox.convertToRestId(mailbox.item.itemId, Office.MailboxEnums.RestVersion.v2_0);
        fetch(mailbox.restUrl + "/v2.0/me/messages/" + encodeURIComponent(id) + "/$value", {
          headers: { Authorization: "Bearer " + res.value },
        })
          .then(function (r) {
            if (!r.ok) throw new Error("REST " + r.status);
            return r.text();
          })
          .then(resolve, reject);
      });
    });
  }

  // (c) Assemble a message from parts: the real internet headers (so Authentication-Results
  // survives) plus the body. Attachments aren't included.
  var DROP_HEADERS = /^(content-type|content-transfer-encoding|mime-version|content-length)$/i;

  function stripMimeHeaders(raw) {
    var out = [];
    var keep = true;
    raw.replace(/\r\n/g, "\n").split("\n").forEach(function (line) {
      if (/^[ \t]/.test(line)) {
        if (keep) out.push(line); // continuation of the previous header
        return;
      }
      if (!line.trim()) return;
      var name = line.split(":", 1)[0];
      keep = !DROP_HEADERS.test(name.trim());
      if (keep) out.push(line);
    });
    return out.join("\r\n");
  }

  function headerSafe(s) {
    return String(s || "").replace(/[\r\n]+/g, " ");
  }

  function basicHeaders(item) {
    var from = item.from || {};
    var lines = [
      "From: " + (from.displayName ? '"' + headerSafe(from.displayName).replace(/"/g, "'") + '" ' : "") +
        "<" + headerSafe(from.emailAddress) + ">",
      "Subject: " + headerSafe(item.subject),
    ];
    if (item.to && item.to.length) {
      lines.push("To: " + item.to.map(function (r) { return headerSafe(r.emailAddress); }).join(", "));
    }
    if (item.dateTimeCreated) lines.push("Date: " + new Date(item.dateTimeCreated).toUTCString());
    return lines.join("\r\n");
  }

  function getHeaders(item) {
    return new Promise(function (resolve) {
      if (!supports("1.8") || typeof item.getAllInternetHeadersAsync !== "function") {
        resolve(basicHeaders(item));
        return;
      }
      item.getAllInternetHeadersAsync(function (res) {
        if (res.status === Office.AsyncResultStatus.Succeeded && res.value) {
          resolve(stripMimeHeaders(res.value));
        } else {
          resolve(basicHeaders(item));
        }
      });
    });
  }

  function getBody(item) {
    function attempt(type) {
      return new Promise(function (resolve, reject) {
        item.body.getAsync(type, function (res) {
          if (res.status === Office.AsyncResultStatus.Succeeded) resolve(res.value || "");
          else reject(new Error("body " + type));
        });
      });
    }
    return attempt(Office.CoercionType.Html)
      .then(function (html) { return { type: "text/html", body: html }; })
      .catch(function () {
        return attempt(Office.CoercionType.Text).then(function (text) { return { type: "text/plain", body: text }; });
      });
  }

  function readAssembled() {
    var item = Office.context.mailbox.item;
    return Promise.all([getHeaders(item), getBody(item)]).then(function (parts) {
      return (
        parts[0] +
        "\r\nMIME-Version: 1.0\r\nContent-Type: " + parts[1].type +
        '; charset="utf-8"\r\nContent-Transfer-Encoding: 8bit\r\n\r\n' +
        parts[1].body
      );
    });
  }

  function readMessage() {
    return readAsFile()
      .then(function (raw) { return { raw: raw, source: "file" }; })
      .catch(function () {
        return readViaRest().then(function (raw) { return { raw: raw, source: "rest" }; });
      })
      .catch(function () {
        return readAssembled().then(function (raw) { return { raw: raw, source: "assembled" }; });
      });
  }

  // ---- API ----------------------------------------------------------------------------------

  function apiPost(path, body) {
    return fetch(API_BASE + path, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + getKey() },
      body: JSON.stringify(body),
    }).then(
      function (r) {
        if (!r.ok) return { ok: false, status: r.status };
        return r.json().then(
          function (data) { return { ok: true, data: data }; },
          function () { return { ok: false, status: 0 }; }
        );
      },
      function () { return { ok: false, status: 0 }; }
    );
  }

  function cacheKey() {
    return "cordon:analysis:" + state.itemId;
  }

  function cachedAnalysis() {
    try {
      var hit = sessionStorage.getItem(cacheKey());
      var data = hit ? JSON.parse(hit) : null;
      return data && data.verdict ? data : null;
    } catch (e) {
      return null;
    }
  }

  function storeAnalysis(data) {
    try {
      sessionStorage.setItem(cacheKey(), JSON.stringify(data));
    } catch (e) { /* storage unavailable: just don't cache */ }
  }

  function errorFor(status) {
    if (status === 401) return null; // handled by the key card
    if (status === 429) return ["Slow down a little", "Too many requests with this key in the last minute. Try again shortly."];
    if (status === 413) return ["Email too large", "This message is bigger than Cordon accepts for analysis."];
    return ["Couldn't reach Cordon", "Cordon didn't respond with a result. Check your connection and try again."];
  }

  // ---- flow ---------------------------------------------------------------------------------

  function start() {
    var gen = ++state.generation;
    state.raw = null;
    state.analysis = null;
    state.history = [];
    state.busy = false;
    var item = Office.context.mailbox.item;
    if (!item) {
      show(messageCard("Open an email", "Select a message to check it with Cordon."));
      return;
    }
    if (!getKey()) {
      showKeyCard("Paste your Cordon API key to start analyzing email.");
      return;
    }
    changeKeyBtn.hidden = false;
    state.itemId = item.itemId || item.internetMessageId || "current";
    show(el("p", "muted center", "Reading this email…"));

    readMessage().then(
      function (msg) {
        if (gen !== state.generation) return;
        state.raw = msg.raw;
        state.source = msg.source;
        var cached = cachedAnalysis();
        if (cached) {
          state.analysis = cached;
          render();
          return;
        }
        analyze(gen);
      },
      function (err) {
        if (gen !== state.generation) return;
        show(messageCard("Couldn't read this email", "Outlook didn't let the add-in read this message. Outlook said: " +
          ((err && err.message) || err), true, [button("Try again", start)]));
      }
    );
  }

  function analyze(gen) {
    show(el("p", "muted center", "Analyzing with Cordon…"));
    apiPost("/v1/analyze/email", { raw_email: state.raw, persist: "if_not_clean" }).then(function (res) {
      if (gen !== state.generation) return;
      if (res.ok && res.data && res.data.verdict) {
        state.analysis = res.data;
        storeAnalysis(res.data);
        render();
        return;
      }
      if (res.status === 401) {
        showKeyCard("Cordon didn't accept the saved key; it may have been revoked. Paste a valid key.", true);
        return;
      }
      var e = errorFor(res.status);
      show(messageCard(e[0], e[1], true, res.status === 413 ? [] : [button("Try again", function () { analyze(gen); })]));
    });
  }

  // ---- rendering ----------------------------------------------------------------------------

  var LABELS = { malicious: "Malicious", suspicious: "Suspicious", clean: "Clean" };

  function verdictCard(r) {
    var v = LABELS[r.verdict] ? r.verdict : "suspicious";
    var card = el("section", "card verdict " + v);
    card.setAttribute("aria-label", "Cordon verdict");

    var head = el("div", "verdict-head");
    head.appendChild(el("span", "pill " + v, LABELS[v]));
    var score = el("span", "score");
    score.appendChild(el("b", "", r.score));
    score.appendChild(document.createTextNode(" / 100 risk"));
    head.appendChild(score);
    card.appendChild(head);
    card.appendChild(el("p", "", r.summary || ""));

    var inds = r.top_indicators || [];
    if (inds.length) {
      card.appendChild(el("div", "section-label", "Top indicators"));
      var ul = el("ul", "indicators");
      inds.forEach(function (t) { ul.appendChild(el("li", "", t)); });
      card.appendChild(ul);
    }

    card.appendChild(el("div", "section-label", "Sender authentication"));
    var auth = el("div", "auth");
    ["spf", "dkim", "dmarc"].forEach(function (k) {
      var val = (r.auth && r.auth[k]) || "none";
      var span = el("span", "");
      span.appendChild(document.createTextNode(k.toUpperCase() + " "));
      span.appendChild(el("span", /^(pass|fail|none)$/.test(val) ? val : "none", val));
      auth.appendChild(span);
    });
    card.appendChild(auth);

    var fw = r.frameworks || [];
    if (fw.length) {
      card.appendChild(el("div", "section-label", "Framework mappings"));
      var chips = el("div", "chips");
      fw.forEach(function (t) { chips.appendChild(el("span", "chip", t)); });
      card.appendChild(chips);
    }

    if (state.source === "assembled") {
      card.appendChild(el("p", "note", "Analyzed from this email's headers and body; attachments weren't included."));
    }
    if (r.verdict === "clean") {
      card.appendChild(el("p", "note", "Clean results aren't saved to Cordon."));
    }
    return card;
  }

  function chatPanel() {
    var chat = el("section", "chat");
    chat.setAttribute("aria-label", "Ask Cordon about this email");
    var messages = el("div", "messages");
    messages.setAttribute("role", "log");
    messages.appendChild(el("div", "bubble bot", "Ask me anything about this email: whether it's phishing, why, the sender, the links, or what to do."));
    chat.appendChild(messages);

    var starters = el("div", "starters");
    STARTERS.forEach(function (q) {
      var b = el("button", "starter", q);
      b.type = "button";
      b.addEventListener("click", function () { send(q); });
      starters.appendChild(b);
    });
    chat.appendChild(starters);

    var composer = el("form", "composer");
    var input = el("textarea");
    input.rows = 1;
    input.maxLength = 1000;
    input.placeholder = "Ask about this email…";
    input.setAttribute("aria-label", "Your question");
    var sendBtn = el("button", "btn", "Send");
    sendBtn.type = "submit";
    composer.appendChild(input);
    composer.appendChild(sendBtn);
    chat.appendChild(composer);

    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        composer.requestSubmit ? composer.requestSubmit() : send(input.value);
      }
    });
    composer.addEventListener("submit", function (e) {
      e.preventDefault();
      send(input.value);
    });

    function add(role, text, extra) {
      var b = el("div", "bubble " + role + (extra ? " " + extra : ""), text);
      messages.appendChild(b);
      messages.scrollTop = messages.scrollHeight;
      return b;
    }

    function setBusy(busy) {
      state.busy = busy;
      sendBtn.disabled = busy;
      input.disabled = busy;
      Array.prototype.forEach.call(starters.children, function (b) { b.disabled = busy; });
    }

    function send(text) {
      var question = String(text || "").trim();
      if (!question || state.busy) return;
      var gen = state.generation;
      input.value = "";
      starters.hidden = true;
      add("user", question);
      var typing = el("div", "typing", "Cordon is thinking…");
      messages.appendChild(typing);
      messages.scrollTop = messages.scrollHeight;
      setBusy(true);

      var history = state.history.slice(-HISTORY_LIMIT);
      apiPost("/v1/assistant", { raw_email: state.raw, question: question, history: history }).then(function (res) {
        if (gen !== state.generation) return;
        typing.remove();
        setBusy(false);
        if (res.ok && res.data && typeof res.data.answer === "string") {
          add("bot", res.data.answer, res.data.refused ? "refused" : "");
          state.history.push({ role: "user", content: question.slice(0, 4000) });
          state.history.push({ role: "assistant", content: res.data.answer.slice(0, 4000) });
          state.history = state.history.slice(-HISTORY_LIMIT);
        } else if (res.status === 401) {
          showKeyCard("Cordon didn't accept the saved key; it may have been revoked. Paste a valid key.", true);
          return;
        } else {
          var e = errorFor(res.status);
          add("bot", e[0] + ". " + e[1], "error");
        }
        input.focus();
      });
    }

    return chat;
  }

  function render() {
    var wrap = document.createDocumentFragment();
    wrap.appendChild(verdictCard(state.analysis));
    wrap.appendChild(chatPanel());
    var footer = el("div", "row");
    footer.appendChild(button("Re-analyze", function () {
      try { sessionStorage.removeItem(cacheKey()); } catch (e) { /* ignore */ }
      state.history = [];
      analyze(state.generation);
    }, true));
    var open = el("a", "btn btn-secondary", "Open Cordon");
    open.href = "https://app.cordoncybersec.us";
    open.target = "_blank";
    open.rel = "noopener noreferrer";
    open.style.textDecoration = "none";
    footer.appendChild(open);
    wrap.appendChild(footer);
    while (app.firstChild) app.removeChild(app.firstChild);
    app.appendChild(wrap);
  }

  // ---- boot ---------------------------------------------------------------------------------

  changeKeyBtn.addEventListener("click", function () {
    state.generation++;
    showKeyCard("Paste a new Cordon API key to replace the saved one.");
  });

  if (typeof Office === "undefined") {
    show(messageCard("Open this from Outlook", "This page is Cordon's Outlook add-in and only works inside Outlook."));
    return;
  }

  Office.onReady(function (info) {
    if (!info || info.host !== Office.HostType.Outlook) {
      show(messageCard("Open this from Outlook", "This page is Cordon's Outlook add-in and only works inside Outlook."));
      return;
    }
    // Pinned task pane: re-run when the user selects a different message.
    try {
      if (supports("1.5")) {
        Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, function () { start(); });
      }
    } catch (e) { /* not pinnable here */ }
    start();
  });
})();
