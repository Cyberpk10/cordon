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
