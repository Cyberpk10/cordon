/**
 * Cordon for Gmail: a thin client. It sends the open message to Cordon's
 * POST /v1/analyze/email and renders exactly what comes back. All detection happens in the
 * Cordon backend. This file never scores, guesses or adds findings.
 *
 * Opening a message auto-analyzes it (once a key is saved) with persist: "if_not_clean", so
 * only suspicious/malicious mail becomes a Case; clean mail is returned and nothing is saved.
 * Results are cached per message for 6 hours, so re-opening an email doesn't call Cordon again.
 *
 * The API key lives in this user's PropertiesService.getUserProperties(), which only this
 * user's script runs can read. It is never logged.
 *
 * D7 auto-quarantine (owner's own mailbox only; see "Auto-quarantine" at the bottom and the
 * README): a time-driven trigger runs cordonTick(), which sends new inbox mail to Cordon and,
 * when Cordon returns a signed directive for one message, moves exactly that message to the
 * "Cordon Quarantine" label. The decision is Cordon's; this file only executes a directive after
 * re-checking it names the message it read. It never deletes and never acts on a query.
 */

// Must match urlFetchWhitelist in appsscript.json.
var CORDON_API_BASE = 'https://aegis-backend-zbcr.onrender.com';
var CORDON_APP_URL = 'https://app.cordoncybersec.us';
var API_KEY_PROPERTY = 'CORDON_API_KEY';
// Only suspicious/malicious results are saved as Cases (see /v1/analyze/email "persist").
var PERSIST_MODE = 'if_not_clean';
// CacheService max is 6 hours. Re-opening a message within this window reuses the result.
var RESULT_CACHE_SECONDS = 6 * 60 * 60;

// Cordon palette.
var COLORS = {
  accent: '#5a6cf0',
  danger: '#e85656',
  success: '#4ecb86',
  warning: '#e6aa46',
  muted: '#8a8fa3'
};

var VERDICT_STYLE = {
  malicious: { label: 'Malicious', color: COLORS.danger },
  suspicious: { label: 'Suspicious', color: COLORS.warning },
  clean: { label: 'Clean', color: COLORS.success }
};

var AUTH_COLOR = { pass: COLORS.success, fail: COLORS.danger, none: COLORS.muted };

// ---- entry points ---------------------------------------------------------------------------

/** Contextual trigger: runs whenever the user opens a message. With a key saved it analyzes
 * the message right away, unless a result for it is already cached. Failures here stay quiet
 * (a small "Tap to analyze" card); tapping shows the detailed error. */
function onGmailMessageOpen(e) {
  var apiKey = getApiKey_();
  if (!apiKey) {
    return [buildSettingsCard_('Paste your Cordon API key to start analyzing email.')];
  }
  if (isQuarantined_(e)) {
    return [buildQuarantinedCard_()];
  }
  var cached = getCachedResult_(apiKey, e);
  if (cached) {
    return [buildCardForResult_(cached)];
  }
  var outcome = requestAnalysis_(e, apiKey);
  if (outcome.ok) {
    return [buildCardForResult_(outcome.result)];
  }
  if (outcome.status === 401) {
    // Not transient: auto-analysis can't work until the key is fixed.
    return [buildBadKeyCard_()];
  }
  return [buildAnalyzePromptCard_()];
}

/** Homepage (no message open): lets the user set or change the key. */
function onHomepage(e) {
  var message = getApiKey_()
    ? 'Open any email to analyze it with Cordon. You can replace your API key below.'
    : 'Paste your Cordon API key, then open any email to analyze it.';
  return buildSettingsCard_(message);
}

// ---- actions --------------------------------------------------------------------------------

function saveApiKey(e) {
  var key = String(formValue_(e, 'apiKey') || '').trim();
  if (key.indexOf('cdn_') !== 0) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification()
        .setText('That doesn\'t look like a Cordon API key (it should start with "cdn_").'))
      .build();
  }
  PropertiesService.getUserProperties().setProperty(API_KEY_PROPERTY, key);

  var builder = CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Cordon API key saved.'));
  if (e && e.gmail && e.gmail.messageId) {
    // A message is open: analyze it now, as opening it would have.
    builder.setNavigation(CardService.newNavigation().updateCard(analyzeAndBuildCard_(e)));
  } else {
    builder.setNavigation(CardService.newNavigation().updateCard(
      buildSettingsCard_('Saved. Open any email to analyze it with Cordon.')));
  }
  return builder.build();
}

function showSettings(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(
      buildSettingsCard_('Paste a new Cordon API key to replace the saved one.')))
    .build();
}

/** "Analyze" / "Re-analyze": always calls Cordon (skips the cache) and shows any error in full. */
function analyzeMessage(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(analyzeAndBuildCard_(e)))
    .build();
}

function retryAnalysis(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(analyzeAndBuildCard_(e)))
    .build();
}

// ---- analysis -------------------------------------------------------------------------------

/** Tap path: analyze now, bypassing the cache, and explain any failure. */
function analyzeAndBuildCard_(e) {
  var apiKey = getApiKey_();
  if (!apiKey) {
    return buildSettingsCard_('Paste your Cordon API key to start analyzing email.');
  }
  var outcome = requestAnalysis_(e, apiKey);
  if (outcome.ok) {
    return buildCardForResult_(outcome.result);
  }
  switch (outcome.reason) {
    case 'read':
      // Google's own error text: if the open-message scope doesn't cover getRawContent(),
      // this is where it surfaces, and the exact message is what we need to see.
      return buildErrorCard_('Couldn\'t read this email',
        'Gmail didn\'t let the add-on read this message. Gmail said: ' + outcome.detail, true);
    case 'http':
      if (outcome.status === 401) return buildBadKeyCard_();
      if (outcome.status === 429) {
        return buildErrorCard_('Slow down a little',
          'Too many emails analyzed with this key in the last minute. Try again shortly.', true);
      }
      if (outcome.status === 413) {
        return buildErrorCard_('Email too large',
          'This message is bigger than Cordon accepts for analysis.', false);
      }
      return buildUnreachableCard_();
    default:
      return buildUnreachableCard_();
  }
}

/** Reads the open message and calls Cordon once. Returns {ok: true, result} or
 * {ok: false, reason: 'read'|'network'|'http'|'response', status?, detail?}. Caches successes. */
function requestAnalysis_(e, apiKey) {
  var raw;
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    raw = GmailApp.getMessageById(e.gmail.messageId).getRawContent();
  } catch (err) {
    return { ok: false, reason: 'read', detail: String((err && err.message) || err) };
  }

  var response;
  try {
    response = UrlFetchApp.fetch(CORDON_API_BASE + '/v1/analyze/email', {
      method: 'post',
      contentType: 'application/json',
      headers: { Authorization: 'Bearer ' + apiKey },
      payload: JSON.stringify({ raw_email: raw, persist: PERSIST_MODE }),
      muteHttpExceptions: true,
      followRedirects: false
    });
  } catch (err) {
    return { ok: false, reason: 'network' };
  }

  var status = response.getResponseCode();
  if (status !== 200) {
    return { ok: false, reason: 'http', status: status };
  }
  var result;
  try {
    result = JSON.parse(response.getContentText());
  } catch (err) {
    return { ok: false, reason: 'response' };
  }
  if (!result || !VERDICT_STYLE[result.verdict]) {
    return { ok: false, reason: 'response' };
  }
  cacheResult_(apiKey, e, result);
  return { ok: true, result: result };
}

// ---- result cache (CacheService, per user; needs no OAuth scope) ---------------------------

/** Keyed by message id plus the key's public prefix, so switching keys/accounts doesn't show
 * another account's cached result. */
function cacheKey_(apiKey, e) {
  if (!e || !e.gmail || !e.gmail.messageId) return null;
  return 'cordon:' + apiKey.slice(0, 10) + ':' + e.gmail.messageId;
}

function getCachedResult_(apiKey, e) {
  var key = cacheKey_(apiKey, e);
  if (!key) return null;
  try {
    var hit = CacheService.getUserCache().get(key);
    var result = hit ? JSON.parse(hit) : null;
    return result && VERDICT_STYLE[result.verdict] ? result : null;
  } catch (err) {
    return null;  // a cache problem must never block analysis
  }
}

function cacheResult_(apiKey, e, result) {
  var key = cacheKey_(apiKey, e);
  if (!key) return;
  try {
    CacheService.getUserCache().put(key, JSON.stringify(result), RESULT_CACHE_SECONDS);
  } catch (err) {
    // Too large or cache unavailable: just don't cache.
  }
}

// ---- cards ----------------------------------------------------------------------------------

function buildCardForResult_(r) {
  return r.verdict === 'clean' ? buildCleanCard_(r) : buildResultCard_(r);
}

/** Compact card for clean mail. Clean results aren't saved to Cordon (persist: if_not_clean). */
function buildCleanCard_(r) {
  var auth = r.auth || {};
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Cordon: Clean')
      .setSubtitle('Risk score ' + r.score + ' / 100'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        '<font color="' + COLORS.success + '"><b>Clean ✓</b> · nothing suspicious</font>'))
      .addWidget(CardService.newTextParagraph().setText(
        '<font color="' + COLORS.muted + '">' + authLine_(auth) +
        '<br>Not saved to Cordon.</font>'))
      .addWidget(buildFooterButtons_()))
    .build();
}

function buildResultCard_(r) {
  var style = VERDICT_STYLE[r.verdict];
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('Cordon: ' + style.label)
      .setSubtitle('Risk score ' + r.score + ' / 100'));

  // Verdict banner, colored by verdict.
  card.addSection(CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<font color="' + style.color + '"><b>' + style.label.toUpperCase() + '</b> · ' +
      '<b>' + escape_(String(r.score)) + '</b>/100</font>'))
    .addWidget(CardService.newTextParagraph().setText(escape_(r.summary || ''))));

  // Account takeover: a known sender's real (authenticated) account acting out of pattern.
  var ato = r.account_takeover;
  if (ato && ato.explanation) {
    card.addSection(CardService.newCardSection()
      .setHeader(ato.kind === 'lateral' ? '⚠ Internal phishing: compromised colleague' : '⚠ Account takeover')
      .addWidget(CardService.newTextParagraph().setText(
        '<font color="' + COLORS.danger + '">' + escape_(ato.explanation) + '</font>')));
  }

  var indicators = r.top_indicators || [];
  if (indicators.length) {
    var bullets = indicators.map(function (t) { return '• ' + escape_(t); }).join('<br>');
    card.addSection(CardService.newCardSection()
      .setHeader('Top indicators')
      .addWidget(CardService.newTextParagraph().setText(bullets)));
  }

  var auth = r.auth || {};
  card.addSection(CardService.newCardSection()
    .setHeader('Sender authentication')
    .addWidget(CardService.newTextParagraph().setText(authLine_(auth, true))));

  if (r.sender_baseline && r.sender_baseline.summary) {
    card.addSection(CardService.newCardSection()
      .setHeader('Sender history')
      .addWidget(CardService.newTextParagraph().setText(escape_(r.sender_baseline.summary))));
  }

  // Cordon's investigation (recommend-only): confidence, campaign, and what it suggests.
  var inv = r.investigation;
  if (inv && inv.recommended_action) {
    var campaignText = { one_off: 'One-off', possible_campaign: 'Possible campaign', wave: 'Part of a wave hitting your organisation' };
    var lines = [
      '<b>Confidence:</b> ' + escape_(inv.confidence) + ' · <b>Campaign:</b> ' + escape_(campaignText[inv.campaign] || inv.campaign),
      '<b>Hypothesis:</b> ' + escape_(inv.hypothesis),
      '<b>Recommended (not yet done):</b> ' + escape_(inv.recommended_action)
    ];
    if (inv.confidence_note) lines.push('<i>' + escape_(inv.confidence_note) + '</i>');
    card.addSection(CardService.newCardSection()
      .setHeader('Investigation')
      .addWidget(CardService.newTextParagraph().setText(lines.join('<br>'))));
  }

  var frameworks = r.frameworks || [];
  if (frameworks.length) {
    card.addSection(buildFrameworkSection_(frameworks));
  }

  card.addSection(CardService.newCardSection().addWidget(buildFooterButtons_()));
  return card.build();
}

/** SPF/DKIM/DMARC on one line; colored per result when `colored`. */
function authLine_(auth, colored) {
  return ['spf', 'dkim', 'dmarc'].map(function (k) {
    var v = auth[k] || 'none';
    var value = colored
      ? '<font color="' + (AUTH_COLOR[v] || COLORS.muted) + '"><b>' + escape_(v) + '</b></font>'
      : escape_(v);
    return k.toUpperCase() + ' ' + value;
  }).join('   ·   ');
}

/** Re-analyze (fresh call, skips the cache), Open Cordon, API key: on every result card. */
function buildFooterButtons_() {
  return CardService.newButtonSet()
    .addButton(CardService.newTextButton()
      .setText('Re-analyze')
      .setOnClickAction(CardService.newAction().setFunctionName('analyzeMessage')))
    .addButton(CardService.newTextButton()
      .setText('Open Cordon')
      .setOpenLink(CardService.newOpenLink().setUrl(CORDON_APP_URL)))
    .addButton(CardService.newTextButton()
      .setText('API key')
      .setOnClickAction(CardService.newAction().setFunctionName('showSettings')));
}

/** Framework tags as chips where the host supports ChipList, otherwise a plain line. */
function buildFrameworkSection_(frameworks) {
  var section = CardService.newCardSection().setHeader('Framework mappings');
  try {
    var chips = CardService.newChipList().setLayout(CardService.ChipListLayout.WRAPPED);
    frameworks.forEach(function (tag) {
      chips.addChip(CardService.newChip().setLabel(tag));
    });
    section.addWidget(chips);
  } catch (err) {
    section.addWidget(CardService.newTextParagraph().setText(
      frameworks.map(escape_).join('  ·  ')));
  }
  return section;
}

function buildAnalyzePromptCard_() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Cordon'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        'Cordon hasn\'t checked this email yet. Tap to analyze it; only suspicious or ' +
        'malicious results are saved as Cases.'))
      .addWidget(CardService.newTextButton()
        .setText('Tap to analyze')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction().setFunctionName('analyzeMessage')))
      .addWidget(CardService.newTextButton()
        .setText('API key')
        .setOnClickAction(CardService.newAction().setFunctionName('showSettings'))))
    .build();
}

function buildSettingsCard_(message, isError) {
  var text = isError
    ? '<font color="' + COLORS.danger + '"><b>' + escape_(message) + '</b></font>'
    : escape_(message);
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Cordon settings'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(text))
      .addWidget(CardService.newTextInput()
        .setFieldName('apiKey')
        .setTitle('Cordon API key')
        .setHint('Create one in Cordon: Settings → API keys. Starts with cdn_'))
      .addWidget(CardService.newTextButton()
        .setText('Save')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction().setFunctionName('saveApiKey'))))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextButton()
        .setText('Get a key in Cordon')
        .setOpenLink(CardService.newOpenLink().setUrl(CORDON_APP_URL))))
    .build();
}

function buildBadKeyCard_() {
  return buildSettingsCard_('Check your Cordon API key. Cordon didn\'t accept the saved key; ' +
    'it may have been revoked. Paste a valid key below.', true);
}

function buildUnreachableCard_() {
  return buildErrorCard_('Couldn\'t reach Cordon',
    'Cordon didn\'t respond with a result. Check your connection and try again in a moment.', true);
}

function buildErrorCard_(title, message, canRetry) {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(escape_(message)));
  if (canRetry) {
    section.addWidget(CardService.newTextButton()
      .setText('Try again')
      .setOnClickAction(CardService.newAction().setFunctionName('retryAnalysis')));
  }
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle(title))
    .addSection(section)
    .build();
}

// ---- helpers --------------------------------------------------------------------------------

function getApiKey_() {
  return PropertiesService.getUserProperties().getProperty(API_KEY_PROPERTY);
}

/** Reads a form field from either event-object shape (legacy formInput or commonEventObject). */
function formValue_(e, name) {
  if (!e) return null;
  var common = e.commonEventObject && e.commonEventObject.formInputs &&
    e.commonEventObject.formInputs[name];
  if (common && common.stringInputs && common.stringInputs.value) {
    return common.stringInputs.value[0];
  }
  return e.formInput ? e.formInput[name] : null;
}

/** API text is rendered inside CardService's small HTML subset; escape it so a title can
 * never inject markup into the card. */
function escape_(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}


// ---- D7 auto-quarantine (owner's own mailbox) ----------------------------------------------
//
// Setup (README "Auto-quarantine"): run setupAutoQuarantine() once from the editor, run
// runCalibration() and review the report in Cordon, enable it in Cordon, then add a
// time-driven trigger for cordonTick (every 5 minutes) in the editor's Triggers panel.
//
// Everything here uses the Advanced Gmail service under gmail.modify. GmailApp is not used for
// the loop: Google documents most GmailApp methods as needing the full https://mail.google.com/
// scope, which this add-on does not request. The move is message-level
// (users.messages.modify on one id); GmailApp's label methods are thread-level and would move
// other messages in the same thread.

var D7_LABEL = 'Cordon Quarantine';
var D7_CHECKPOINT_PROPERTY = 'CORDON_D7_CHECKPOINT';
var D7_MAILBOX_PROPERTY = 'CORDON_D7_MAILBOX';
var D7_CALIBRATION_PROPERTY = 'CORDON_D7_CALIBRATION';
var D7_MAX_PER_TICK = 20;
var D7_CALIBRATION_MAX = 300;
var D7_CALIBRATION_BATCH = 10;
var D7_RUN_BUDGET_MS = 4.5 * 60 * 1000;  // Apps Script stops a run at 6 minutes
var GMAIL_ID_RE = /^[0-9a-f]{10,32}$/;

/** Run once from the editor: creates the label, records your address, starts the checkpoint
 * at "now" so older mail is never auto-moved (calibration covers that, read-only). */
function setupAutoQuarantine() {
  var mailbox = mailbox_(true);
  var labelId = ensureLabel_();
  var props = PropertiesService.getUserProperties();
  if (!props.getProperty(D7_CHECKPOINT_PROPERTY)) {
    props.setProperty(D7_CHECKPOINT_PROPERTY, String(Math.floor(Date.now() / 1000)));
  }
  Logger.log('Auto-quarantine ready for %s (label id %s). Next: runCalibration(), then enable it in Cordon, ' +
    'then add a time-driven trigger for cordonTick every 5 minutes.', mailbox, labelId);
}

/** The loop. Safe to run by hand; the trigger runs it every 5 minutes. */
function cordonTick() {
  var apiKey = getApiKey_();
  if (!apiKey) return;
  var lock = LockService.getUserLock();
  if (!lock.tryLock(1000)) return;  // a previous tick is still running
  try {
    var mailbox = mailbox_(false);
    var labelId = ensureLabel_();

    // 1. Undos queued from the Cordon app, and quarantined mail you dragged back yourself.
    var pending = d7Call_(apiKey, 'get', '/v1/remediation/pending?mailbox=' + encodeURIComponent(mailbox));
    if (pending.ok) {
      (pending.body.undos || []).forEach(function (d) { safeExecute_(apiKey, d, labelId); });
      (pending.body.quarantined || []).forEach(function (q) { checkManualRestore_(apiKey, mailbox, q, labelId); });
    }

    // 2. New inbox mail since the checkpoint, oldest first. The search is discovery only
    // (read-only); each message is analyzed, and acted on, individually by its own id.
    var props = PropertiesService.getUserProperties();
    var since = Number(props.getProperty(D7_CHECKPOINT_PROPERTY) || Math.floor(Date.now() / 1000) - 600);
    var listed = Gmail.Users.Messages.list('me', { q: 'in:inbox after:' + since, maxResults: 100 });
    var ids = (listed.messages || []).map(function (m) { return m.id; }).reverse().slice(0, D7_MAX_PER_TICK);
    var cache = CacheService.getUserCache();
    var newest = since;
    ids.forEach(function (id) {
      var seenKey = 'cordon:d7:seen:' + id;
      var msg = readMessage_(id);
      if (!msg) return;
      newest = Math.max(newest, Math.floor(Number(msg.internalDate) / 1000));
      if (cache.get(seenKey)) return;
      if (msg.labelIds.indexOf(labelId) >= 0 || msg.isCordonNotice) {
        cache.put(seenKey, '1', 21600);
        return;
      }
      var res = d7Call_(apiKey, 'post', '/v1/remediation/inbound', {
        raw_email: msg.raw, gmail_message_id: id, mailbox: mailbox,
        fingerprint: msg.fingerprint, from_addr: msg.fromAddr
      });
      if (!res.ok) return;  // retried next tick (not marked seen)
      cache.put(seenKey, '1', 21600);
      if (res.body.directive) safeExecute_(apiKey, res.body.directive, labelId);
    });
    props.setProperty(D7_CHECKPOINT_PROPERTY, String(newest));
  } finally {
    lock.releaseLock();
  }
}

function safeExecute_(apiKey, d, labelId) {
  try {
    return executeDirective_(apiKey, d, labelId);
  } catch (err) {
    console.warn('Cordon directive refused: ' + ((err && err.message) || err));
    return 'refused';
  }
}

/** Executes exactly ONE directive for ONE message. Refuses anything else outright. */
function executeDirective_(apiKey, d, labelId) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) throw new Error('Expected exactly one directive.');
  ['query', 'q', 'ids', 'messages', 'gmail_message_ids'].forEach(function (k) {
    if (Object.prototype.hasOwnProperty.call(d, k)) throw new Error('Directives never carry a query or a list.');
  });
  if (typeof d.gmail_message_id !== 'string' || !GMAIL_ID_RE.test(d.gmail_message_id)) {
    throw new Error('Directive must name one Gmail message id.');
  }
  if (d.kind !== 'move' && d.kind !== 'undo') throw new Error('Unknown directive kind.');
  if (d.label !== D7_LABEL) throw new Error('Unexpected label.');
  if (!(Date.parse(d.expires_at) > Date.now())) return 'expired';

  var id = d.gmail_message_id;
  var meta = readMeta_(id);
  if (!meta) return report_(apiKey, d, 'aborted', 'Message not found.');
  // The id must still name the message Cordon analyzed: same sender + subject fingerprint.
  if (meta.fingerprint !== d.fingerprint) return report_(apiKey, d, 'aborted', 'Fingerprint mismatch.');
  if (d.kind === 'move' && meta.labelIds.indexOf('INBOX') < 0) {
    return report_(apiKey, d, 'aborted', 'No longer in the inbox.');
  }

  var claim = d7Call_(apiKey, 'post', '/v1/remediation/directives/' + d.id + '/claim', { directive: d });
  if (!claim.ok || !claim.body.go) return 'no_go';

  try {
    if (d.kind === 'move') {
      Gmail.Users.Messages.modify({ addLabelIds: [labelId], removeLabelIds: ['INBOX'] }, 'me', id);
    } else {
      Gmail.Users.Messages.modify({ addLabelIds: ['INBOX'], removeLabelIds: [labelId] }, 'me', id);
    }
  } catch (err) {
    return report_(apiKey, d, 'failed', String((err && err.message) || err).slice(0, 300));
  }
  var res = d7Call_(apiKey, 'post', '/v1/remediation/directives/' + d.id + '/result',
    { directive: d, status: 'executed', detail: null });
  if (d.kind === 'move' && res.ok && res.body.insert_notice) insertNotice_(meta);
  return 'executed';
}

function report_(apiKey, d, status, detail) {
  d7Call_(apiKey, 'post', '/v1/remediation/directives/' + d.id + '/result',
    { directive: d, status: status, detail: detail });
  return status;
}

function checkManualRestore_(apiKey, mailbox, q, labelId) {
  if (!q || typeof q.gmail_message_id !== 'string' || !GMAIL_ID_RE.test(q.gmail_message_id)) return;
  var meta = readMeta_(q.gmail_message_id);
  if (!meta) return;
  if (meta.labelIds.indexOf('INBOX') >= 0 || meta.labelIds.indexOf(labelId) < 0) {
    d7Call_(apiKey, 'post', '/v1/remediation/manual-restore',
      { action_id: q.action_id, gmail_message_id: q.gmail_message_id, mailbox: mailbox });
  }
}

/** One-shot, read-only backtest. Run from the editor; if it stops for time, run it again and
 * it continues where it left off. The report is in Cordon: Settings → Auto-quarantine. */
function runCalibration() {
  var apiKey = getApiKey_();
  if (!apiKey) throw new Error('Save your Cordon API key in the add-on first.');
  var mailbox = mailbox_(false);
  var props = PropertiesService.getUserProperties();
  var state = JSON.parse(props.getProperty(D7_CALIBRATION_PROPERTY) || 'null');
  if (!state) {
    var start = d7Call_(apiKey, 'post', '/v1/remediation/calibration', { mailbox: mailbox });
    if (!start.ok) throw new Error('Cordon refused to start calibration (HTTP ' + start.status + ').');
    state = { runId: start.body.run_id, pageToken: null, done: 0 };
  }
  var started = Date.now();
  var finished = false;
  while (Date.now() - started < D7_RUN_BUDGET_MS) {
    var page = Gmail.Users.Messages.list('me',
      { q: 'in:inbox newer_than:30d', maxResults: 50, pageToken: state.pageToken || undefined });
    var ids = (page.messages || []).map(function (m) { return m.id; });
    for (var i = 0; i < ids.length && state.done < D7_CALIBRATION_MAX; i += D7_CALIBRATION_BATCH) {
      var batch = ids.slice(i, i + D7_CALIBRATION_BATCH).map(readMessage_).filter(function (m) { return m; })
        .map(function (m) {
          return { raw_email: m.raw, gmail_message_id: m.id,
            received_at: new Date(Number(m.internalDate)).toISOString() };
        });
      if (batch.length) {
        var res = d7Call_(apiKey, 'post', '/v1/remediation/calibration/' + state.runId + '/batch',
          { mailbox: mailbox, messages: batch });
        if (!res.ok) throw new Error('Calibration batch failed (HTTP ' + res.status + '). Run again to retry.');
      }
      state.done += batch.length;
    }
    state.pageToken = page.nextPageToken || null;
    if (!state.pageToken || state.done >= D7_CALIBRATION_MAX) { finished = true; break; }
    props.setProperty(D7_CALIBRATION_PROPERTY, JSON.stringify(state));
  }
  if (!finished) {
    props.setProperty(D7_CALIBRATION_PROPERTY, JSON.stringify(state));
    Logger.log('Calibrated %s messages so far. Run runCalibration() again to continue.', state.done);
    return;
  }
  var done = d7Call_(apiKey, 'post', '/v1/remediation/calibration/' + state.runId + '/complete', { mailbox: mailbox });
  props.deleteProperty(D7_CALIBRATION_PROPERTY);
  if (!done.ok) throw new Error('Could not complete calibration (HTTP ' + done.status + ').');
  Logger.log('Calibration done: %s messages, %s would be auto-moved at floor %s. Review it in Cordon: ' +
    'Settings → Auto-quarantine.', done.body.total, done.body.would_move, done.body.score_floor);
}

// ---- sidebar: quarantined message -----------------------------------------------------------

function isQuarantined_(e) {
  try {
    if (!e || !e.gmail || !e.gmail.messageId) return false;
    var labelId = findLabelId_();
    if (!labelId) return false;
    var meta = Gmail.Users.Messages.get('me', e.gmail.messageId, { format: 'minimal' });
    return (meta.labelIds || []).indexOf(labelId) >= 0;
  } catch (err) {
    return false;  // never let this block the normal card
  }
}

function buildQuarantinedCard_() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Cordon: moved to quarantine'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        '<font color="' + COLORS.danger + '"><b>Moved to "' + D7_LABEL + '" by Cordon.</b></font> ' +
        'Nothing was deleted. If this is not phishing, undo puts it back in your inbox and tells Cordon ' +
        'the rules got it wrong.'))
      .addWidget(CardService.newTextButton()
        .setText('Undo / Not phishing')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction().setFunctionName('undoQuarantine')))
      .addWidget(buildFooterButtons_()))
    .build();
}

function undoQuarantine(e) {
  var apiKey = getApiKey_();
  var text;
  try {
    var res = d7Call_(apiKey, 'post', '/v1/remediation/undo',
      { gmail_message_id: e.gmail.messageId, mailbox: mailbox_(false) });
    if (!res.ok) {
      text = 'Cordon could not undo this (HTTP ' + res.status + ').';
    } else {
      var outcome = executeDirective_(apiKey, res.body.directive, ensureLabel_());
      text = outcome === 'executed' ? 'Restored to your inbox.' : 'Undo did not complete (' + outcome + ').';
    }
  } catch (err) {
    text = 'Undo failed: ' + ((err && err.message) || err);
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}

// ---- Gmail helpers (Advanced Gmail service, gmail.modify) ----------------------------------

function mailbox_(refresh) {
  var props = PropertiesService.getUserProperties();
  var cached = props.getProperty(D7_MAILBOX_PROPERTY);
  if (cached && !refresh) return cached;
  var address = String(Gmail.Users.getProfile('me').emailAddress).toLowerCase();
  props.setProperty(D7_MAILBOX_PROPERTY, address);
  return address;
}

function findLabelId_() {
  var labels = Gmail.Users.Labels.list('me').labels || [];
  for (var i = 0; i < labels.length; i++) {
    if (labels[i].name === D7_LABEL) return labels[i].id;
  }
  return null;
}

function ensureLabel_() {
  return findLabelId_() || Gmail.Users.Labels.create(
    { name: D7_LABEL, labelListVisibility: 'labelShow', messageListVisibility: 'show' }, 'me').id;
}

function header_(headers, name) {
  for (var i = 0; i < (headers || []).length; i++) {
    if (String(headers[i].name).toLowerCase() === name.toLowerCase()) return String(headers[i].value || '');
  }
  return '';
}

function fromAddress_(from) {
  var m = /<([^>]+)>/.exec(from);
  return (m ? m[1] : from).trim().toLowerCase();
}

/** sha256(lowercase From address + "\n" + Subject), hex. The same function runs when the
 * message is read for analysis and again right before acting on a directive. */
function fingerprintOf_(fromAddr, subject) {
  var bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, fromAddr + '\n' + subject,
    Utilities.Charset.UTF_8);
  return bytes.map(function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('');
}

function readMeta_(id) {
  try {
    var m = Gmail.Users.Messages.get('me', id, { format: 'metadata', metadataHeaders: ['From', 'Subject'] });
    var headers = m.payload && m.payload.headers;
    var fromAddr = fromAddress_(header_(headers, 'From'));
    var subject = header_(headers, 'Subject');
    return { id: id, labelIds: m.labelIds || [], fromAddr: fromAddr, subject: subject,
      fingerprint: fingerprintOf_(fromAddr, subject) };
  } catch (err) {
    return null;
  }
}

function readMessage_(id) {
  var meta = readMeta_(id);
  if (!meta) return null;
  try {
    var full = Gmail.Users.Messages.get('me', id, { format: 'raw' });
    var raw = Utilities.newBlob(Utilities.base64DecodeWebSafe(full.raw)).getDataAsString();
    meta.raw = raw;
    meta.internalDate = full.internalDate;
    meta.isCordonNotice = /^X-Cordon-Notice:/mi.test(raw.split(/\r?\n\r?\n/)[0]);
    return meta;
  } catch (err) {
    return null;
  }
}

/** Optional notice email (Settings → Auto-quarantine → email notice). Inserted straight into
 * your own inbox with users.messages.insert (covered by gmail.modify), so no send scope. */
function insertNotice_(meta) {
  try {
    var mailbox = mailbox_(false);
    var body = 'Cordon moved a message out of your inbox into the "' + D7_LABEL + '" label.\r\n\r\n' +
      'From: ' + meta.fromAddr + '\r\nSubject: ' + meta.subject + '\r\n\r\n' +
      'Nothing was deleted. Not phishing? Open it in the "' + D7_LABEL + '" label and tap ' +
      '"Undo / Not phishing" in the Cordon panel, or use Undo in Cordon.\r\n';
    var rfc822 = 'From: Cordon <' + mailbox + '>\r\nTo: ' + mailbox + '\r\n' +
      'Subject: Cordon quarantined a message\r\nX-Cordon-Notice: 1\r\n' +
      'Content-Type: text/plain; charset=UTF-8\r\n\r\n' + body;
    Gmail.Users.Messages.insert({ raw: Utilities.base64EncodeWebSafe(rfc822, Utilities.Charset.UTF_8),
      labelIds: ['INBOX', 'UNREAD'] }, 'me');
  } catch (err) {
    console.warn('Cordon notice not inserted: ' + ((err && err.message) || err));
  }
}

function d7Call_(apiKey, method, path, payload) {
  var options = {
    method: method,
    headers: { Authorization: 'Bearer ' + apiKey },
    muteHttpExceptions: true,
    followRedirects: false
  };
  if (payload) {
    options.contentType = 'application/json';
    options.payload = JSON.stringify(payload);
  }
  try {
    var r = UrlFetchApp.fetch(CORDON_API_BASE + path, options);
    var status = r.getResponseCode();
    var body = null;
    try { body = JSON.parse(r.getContentText()); } catch (err) { body = null; }
    return { ok: status === 200 && body !== null, status: status, body: body };
  } catch (err) {
    return { ok: false, status: 0, body: null };
  }
}
