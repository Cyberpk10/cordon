/**
 * Cordon for Gmail: a thin client. When a message is opened it sends the raw message to
 * Cordon's POST /v1/analyze/email and renders exactly what comes back. All detection
 * happens in the Cordon backend. This file never scores, guesses or adds findings.
 *
 * The API key lives in this user's PropertiesService.getUserProperties(), which only this
 * user's script runs can read. It is never logged.
 */

// Must match urlFetchWhitelist in appsscript.json.
var CORDON_API_BASE = 'https://aegis-backend-zbcr.onrender.com';
var CORDON_APP_URL = 'https://app.cordoncybersec.us';
var API_KEY_PROPERTY = 'CORDON_API_KEY';

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

/** Contextual trigger: runs whenever the user opens a message. Deliberately does NOT call
 * Cordon: analysis only happens when the user taps Analyze, so reading a normal inbox doesn't
 * turn every newsletter into a Case or burn through the per-key rate limit. */
function onGmailMessageOpen(e) {
  if (!getApiKey_()) {
    return [buildSettingsCard_('Paste your Cordon API key to start analyzing email.')];
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
    // A message is open: offer to analyze it (still the user's choice).
    builder.setNavigation(CardService.newNavigation().updateCard(buildAnalyzePromptCard_()));
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

/** The Analyze button. Also used by "Try again". */
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

function analyzeAndBuildCard_(e) {
  var apiKey = getApiKey_();
  if (!apiKey) {
    return buildSettingsCard_('Paste your Cordon API key to start analyzing email.');
  }

  var raw;
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    raw = GmailApp.getMessageById(e.gmail.messageId).getRawContent();
  } catch (err) {
    // Show Google's own error text: if the open-message scope doesn't cover getRawContent(),
    // this is where it surfaces, and the exact message is what we need to see.
    return buildErrorCard_('Couldn\'t read this email',
      'Gmail didn\'t let the add-on read this message. Gmail said: ' +
      String((err && err.message) || err), true);
  }

  var response;
  try {
    response = UrlFetchApp.fetch(CORDON_API_BASE + '/v1/analyze/email', {
      method: 'post',
      contentType: 'application/json',
      headers: { Authorization: 'Bearer ' + apiKey },
      payload: JSON.stringify({ raw_email: raw }),
      muteHttpExceptions: true,
      followRedirects: false
    });
  } catch (err) {
    return buildUnreachableCard_();
  }

  var status = response.getResponseCode();
  if (status === 401) {
    return buildSettingsCard_('Check your Cordon API key. Cordon didn\'t accept the saved key; ' +
      'it may have been revoked. Paste a valid key below.', true);
  }
  if (status === 429) {
    return buildErrorCard_('Slow down a little',
      'Too many emails analyzed with this key in the last minute. Try again shortly.', true);
  }
  if (status === 413) {
    return buildErrorCard_('Email too large',
      'This message is bigger than Cordon accepts for analysis.', false);
  }
  if (status !== 200) {
    return buildUnreachableCard_();
  }

  var result;
  try {
    result = JSON.parse(response.getContentText());
  } catch (err) {
    return buildUnreachableCard_();
  }
  if (!result || !VERDICT_STYLE[result.verdict]) {
    return buildUnreachableCard_();
  }
  return buildResultCard_(result);
}

// ---- cards ----------------------------------------------------------------------------------

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
    .addWidget(CardService.newTextParagraph().setText(
      ['spf', 'dkim', 'dmarc'].map(function (k) {
        var v = auth[k] || 'none';
        return k.toUpperCase() + ' <font color="' + (AUTH_COLOR[v] || COLORS.muted) + '"><b>' +
          escape_(v) + '</b></font>';
      }).join('   ·   '))));

  var frameworks = r.frameworks || [];
  if (frameworks.length) {
    card.addSection(buildFrameworkSection_(frameworks));
  }

  card.addSection(CardService.newCardSection()
    .addWidget(CardService.newButtonSet()
      .addButton(CardService.newTextButton()
        .setText('Open Cordon')
        .setOpenLink(CardService.newOpenLink().setUrl(CORDON_APP_URL)))
      .addButton(CardService.newTextButton()
        .setText('API key')
        .setOnClickAction(CardService.newAction().setFunctionName('showSettings')))));

  return card.build();
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
        'Check this email for phishing. Analyzing sends it to Cordon and saves the result ' +
        'as a Case in your account.'))
      .addWidget(CardService.newTextButton()
        .setText('Analyze')
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
