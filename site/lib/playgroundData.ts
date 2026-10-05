// Captured from real Cordon analyzer output (POST /api/analyze/text against a local
// backend instance), not fabricated. Every indicator title, description, auth result,
// framework control id and name, and AI analyst narrative sentence below is copied
// verbatim from an actual response. Two narratives were trimmed at their last complete
// sentence, dropping only the dangling fragment the backend's real 300-output-token cap
// (backend/app/reasoning/llm_analyst.py) cut them off at mid-word, nothing was reworded
// or added. To refresh: re-run the same three sample emails through a local backend and
// regenerate this file from the response JSON.

export type PlaygroundVerdict = "malicious" | "suspicious" | "safe";

export interface PlaygroundIndicator {
  id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high";
  score: number;
}

export interface FrameworkControl {
  id: string;
  name: string;
}

export interface PlaygroundSample {
  key: "phishing" | "bec" | "safe";
  label: string;
  email: {
    fromDisplay: string;
    fromAddress: string;
    to: string;
    subject: string;
    body: string;
  };
  verdict: PlaygroundVerdict;
  score: number;
  indicators: PlaygroundIndicator[];
  auth: { spf: string; dkim: string; dmarc: string };
  frameworks: { label: string; key: string; controls: FrameworkControl[] }[];
  narrative: string;
  analystModel: string;
}

export const PLAYGROUND_SAMPLES: PlaygroundSample[] = [
  {
    key: "phishing",
    label: "Credential phishing",
    email: {
      fromDisplay: `PayPal Support`,
      fromAddress: `billing-support@paypa1-secure.com`,
      to: `employee@ourcompany.example`,
      subject: `Urgent: Verify your account within 24 hours`,
      body: `We detected unusual sign-in activity on your account. You must verify your account within 24 hours or your account will be suspended. This is your final notice. Failure to comply will result in permanent account closure.

Verify your account now: https://paypa1-secure.com/verify-account

PayPal Security Team`,
    },
    verdict: "malicious",
    score: 100,
    indicators: [
      {
        id: "LOOKALIKE_DOMAIN",
        title: `Brand name used in an unrelated domain`,
        description: `Domain 'paypa1-secure.com' contains the brand name 'PayPal' but is not the brand's real domain ('paypal.com').`,
        severity: "high",
        score: 20.0,
      },
      {
        id: "URGENCY_LANGUAGE",
        title: `Urgency / pressure language detected`,
        description: `The message uses language designed to pressure the recipient into acting quickly without careful review — a common social-engineering technique.`,
        severity: "high",
        score: 16.0,
      },
      {
        id: "CREDENTIAL_REQUEST",
        title: `Credential-harvesting language detected`,
        description: `The message asks the recipient to verify, confirm, or re-enter login credentials or account details — a hallmark of credential-phishing.`,
        severity: "high",
        score: 30.0,
      },
      {
        id: "LINK_DISPLAY_HREF_MISMATCH",
        title: `Link display text does not match its destination`,
        description: `One or more links show a domain or URL as their visible text but actually point somewhere else — a classic technique to disguise a malicious destination as a trusted one.`,
        severity: "high",
        score: 20.0,
      },
      {
        id: "AUTH_SPF_FAIL",
        title: `SPF authentication failed`,
        description: `The mail server's Authentication-Results header reports SPF=fail for this message, indicating it may not genuinely originate from the claimed sending domain.`,
        severity: "high",
        score: 15.0,
      },
      {
        id: "AUTH_DKIM_FAIL",
        title: `DKIM authentication failed`,
        description: `The mail server's Authentication-Results header reports DKIM=fail for this message, indicating it may not genuinely originate from the claimed sending domain.`,
        severity: "high",
        score: 15.0,
      },
      {
        id: "AUTH_DMARC_FAIL",
        title: `DMARC authentication failed`,
        description: `The mail server's Authentication-Results header reports DMARC=fail for this message, indicating it may not genuinely originate from the claimed sending domain.`,
        severity: "high",
        score: 15.0,
      },
      {
        id: "FIRST_CONTACT_SENDER",
        title: `First contact from this sender`,
        description: `This is the first email this account has received from 'paypa1-secure.com' in the analyzed history window. Not suspicious on its own — most legitimate first contacts look exactly like this — but combined with other signals it raises confidence that a claimed business relationship doesn't actually exist yet.`,
        severity: "low",
        score: 8.0,
      },
      {
        id: "DOMAIN_LOOKS_RANDOMLY_GENERATED",
        title: `Sending domain name looks randomly generated`,
        description: `The domain label 'paypa1-secure' has unusually high character-entropy and mixes letters and digits in a pattern more consistent with an automatically generated or freshly-registered domain than a real organization's brand name. This is a zero-network heuristic proxy, not a verified WHOIS/RDAP registration date.`,
        severity: "medium",
        score: 10.0,
      },
    ],
    auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
    frameworks: [
      {
        label: "MITRE ATT&CK",
        key: "mitre_attack",
        controls: [
          { id: "T1583.001", name: `Acquire Infrastructure: Domains` },
          { id: "T1656", name: `Impersonation` },
          { id: "T1566.002", name: `Phishing: Spearphishing Link` },
          { id: "T1598", name: `Phishing for Information` },
          { id: "T1566", name: `Phishing` },
        ],
      },
      {
        label: "NIST CSF",
        key: "nist_csf",
        controls: [
          { id: "ID.RA-05", name: `Threats, vulnerabilities, likelihoods, and impacts are used to determine risk` },
          { id: "DE.AE-02", name: `Detected events are analyzed to understand attack targets and methods` },
          { id: "PR.AT-01", name: `Personnel are provided awareness and training on phishing and social engineering` },
          { id: "DE.CM-01", name: `Networks and network services are monitored to find potentially adverse events` },
        ],
      },
      {
        label: "ISO 27001",
        key: "iso_27001",
        controls: [
          { id: "A.5.7", name: `Threat intelligence` },
          { id: "A.8.23", name: `Web filtering` },
          { id: "A.6.3", name: `Information security awareness, education and training` },
          { id: "A.5.14", name: `Information transfer` },
        ],
      },
      {
        label: "SOC 2",
        key: "soc2",
        controls: [
          { id: "CC6.6", name: `The entity implements controls to protect against external threats` },
          { id: "CC7.2", name: `The entity monitors system components for anomalies indicative of malicious acts or security events` },
          { id: "CC2.2", name: `The entity communicates information to enable personnel to carry out security responsibilities (incl. phishing awareness)` },
          { id: "CC6.1", name: `Logical access security measures protect against threats from sources outside system boundaries` },
        ],
      },
    ],
    narrative: `# Phishing Risk Assessment

**VERDICT: MALICIOUS | CONFIDENCE: CRITICAL**

## Key Threat Indicators

This is a **high-confidence credential-phishing attack** targeting PayPal users:

1. **Domain Spoofing**: \`paypa1-secure.com\` mimics PayPal's legitimate domain using a numeric substitution (1 for l) — a classic typosquatting technique.

2. **Authentication Failures**: All three email authentication protocols failed (SPF, DKIM, DMARC), confirming the message does not originate from PayPal's infrastructure.

3. **Social Engineering**: 
   - Artificial urgency ("24 hours," "final notice")
   - Account suspension threats
   - Pressures immediate action without verification

4. **Credential Harvesting**: Explicitly requests account verification, designed to capture login credentials on a fake verification page.

5. **URL Deception**: The link visually appears legitimate but directs to the attacker's spoofed domain.

## Recommended Actions

- **Block** the sender domain and similar variations
- **Alert** the targeted user(s)
- **Do not click** any links; verify directly through official PayPal channels
- **Report** to PayPal's abuse team`,
    analystModel: "claude-haiku-4-5",
  },
  {
    key: "bec",
    label: "Invoice fraud (BEC)",
    email: {
      fromDisplay: `Northbridge Logistics, Accounts Payable`,
      fromAddress: `ap@northbridge-logistics-solutions.com`,
      to: `ap-team@ourcompany.example`,
      subject: `Re: Invoice #48213, updated payment details`,
      body: `Hi team,

Following up on our invoice from last month. Our finance team recently changed banks, so this is a change of bank details for our account effective immediately. Please update the details on file before this Friday's payment run so the outstanding invoice does not fall further behind. This is time sensitive, let me know once it is processed.

Thanks,
Northbridge Logistics Accounts Payable`,
    },
    verdict: "malicious",
    score: 100,
    indicators: [
      {
        id: "SENDER_REPLYTO_MISMATCH",
        title: `From and Reply-To domains differ`,
        description: `The email's From address and Reply-To address point to different domains. This is commonly used so replies (e.g. to a credential or payment request) go to an attacker-controlled mailbox instead of the apparent sender.`,
        severity: "medium",
        score: 15.0,
      },
      {
        id: "URGENCY_LANGUAGE",
        title: `Urgency / pressure language detected`,
        description: `The message uses language designed to pressure the recipient into acting quickly without careful review — a common social-engineering technique.`,
        severity: "low",
        score: 4.0,
      },
      {
        id: "PAYMENT_REQUEST",
        title: `Payment / wire-transfer request language detected`,
        description: `The message requests a payment, wire transfer, gift cards, or a change to banking/payment details — common in business-email-compromise (BEC) fraud.`,
        severity: "high",
        score: 30.0,
      },
      {
        id: "AUTH_SPF_FAIL",
        title: `SPF authentication failed`,
        description: `The mail server's Authentication-Results header reports SPF=fail for this message, indicating it may not genuinely originate from the claimed sending domain.`,
        severity: "high",
        score: 15.0,
      },
      {
        id: "AUTH_DKIM_FAIL",
        title: `DKIM authentication failed`,
        description: `The mail server's Authentication-Results header reports DKIM=fail for this message, indicating it may not genuinely originate from the claimed sending domain.`,
        severity: "high",
        score: 15.0,
      },
      {
        id: "AUTH_DMARC_FAIL",
        title: `DMARC authentication failed`,
        description: `The mail server's Authentication-Results header reports DMARC=fail for this message, indicating it may not genuinely originate from the claimed sending domain.`,
        severity: "high",
        score: 15.0,
      },
      {
        id: "FIRST_CONTACT_SENDER",
        title: `First contact from this sender`,
        description: `This is the first email this account has received from 'northbridge-logistics-solutions.com' in the analyzed history window. Not suspicious on its own — most legitimate first contacts look exactly like this — but combined with other signals it raises confidence that a claimed business relationship doesn't actually exist yet.`,
        severity: "low",
        score: 8.0,
      },
      {
        id: "UNKNOWN_VENDOR_CLAIM",
        title: `Claims a vendor/business relationship with no correspondence history`,
        description: `The message uses language implying an existing business or vendor relationship (e.g. a prior conversation, invoice, or recurring review), but 'northbridge-logistics-solutions.com' has no prior correspondence with this account — a common framing for supply-chain and vendor-impersonation phishing that doesn't impersonate a well-known consumer brand.`,
        severity: "medium",
        score: 19.0,
      },
    ],
    auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
    frameworks: [
      {
        label: "MITRE ATT&CK",
        key: "mitre_attack",
        controls: [
          { id: "T1656", name: `Impersonation` },
          { id: "T1598", name: `Phishing for Information` },
          { id: "T1566", name: `Phishing` },
        ],
      },
      {
        label: "NIST CSF",
        key: "nist_csf",
        controls: [
          { id: "DE.AE-02", name: `Detected events are analyzed to understand attack targets and methods` },
          { id: "PR.AT-01", name: `Personnel are provided awareness and training on phishing and social engineering` },
          { id: "ID.RA-05", name: `Threats, vulnerabilities, likelihoods, and impacts are used to determine risk` },
        ],
      },
      {
        label: "ISO 27001",
        key: "iso_27001",
        controls: [
          { id: "A.5.7", name: `Threat intelligence` },
          { id: "A.5.14", name: `Information transfer` },
          { id: "A.6.3", name: `Information security awareness, education and training` },
        ],
      },
      {
        label: "SOC 2",
        key: "soc2",
        controls: [
          { id: "CC6.6", name: `The entity implements controls to protect against external threats` },
          { id: "CC7.2", name: `The entity monitors system components for anomalies indicative of malicious acts or security events` },
          { id: "CC2.2", name: `The entity communicates information to enable personnel to carry out security responsibilities (incl. phishing awareness)` },
          { id: "CC6.1", name: `Logical access security measures protect against threats from sources outside system boundaries` },
        ],
      },
    ],
    narrative: `# Phishing Risk Assessment

**Verdict: MALICIOUS | Risk Score: 100/100**

## Critical Risk Indicators

This is a **high-confidence Business Email Compromise (BEC) attack** targeting accounts-payable processes. Key red flags:

1. **Authentication Failures (45 pts)** – SPF, DKIM, and DMARC all failed. The email does not originate from the claimed domain.

2. **Payment Redirect Scheme (30 pts)** – Requests updated banking details for an invoice payment, a classic BEC tactic to divert funds to attacker accounts.

3. **Spoofed Business Relationship (19 pts)** – Falsely implies an existing vendor relationship ("our invoice from last month") with no prior correspondence history—typical supplier-impersonation framing.

4. **Domain Mismatch (15 pts)** – From and Reply-To addresses differ, routing responses to attacker-controlled mailbox instead of legitimate sender.

5. **Artificial Urgency (4 pts)** – "Time sensitive" and "before Friday's payment run" pressure quick action without verification.

## Recommended Action

**Block and quarantine.** Alert finance/AP teams to verify any recent vendor banking changes through **out-of-band communication**`,
    analystModel: "claude-haiku-4-5",
  },
  {
    key: "safe",
    label: "Safe email",
    email: {
      fromDisplay: `Sarah Chen`,
      fromAddress: `sarah.chen@ourcompany.example`,
      to: `team@ourcompany.example`,
      subject: `Notes from today's planning sync`,
      body: `Hi team,

Sharing notes from today's planning sync. Next week's agenda is the usual: roadmap review on Monday, then design critique Wednesday afternoon. Let me know if I missed anything.

Thanks,
Sarah`,
    },
    verdict: "safe",
    score: 8,
    indicators: [
      {
        id: "FIRST_CONTACT_SENDER",
        title: `First contact from this sender`,
        description: `This is the first email this account has received from 'ourcompany.example' in the analyzed history window. Not suspicious on its own — most legitimate first contacts look exactly like this — but combined with other signals it raises confidence that a claimed business relationship doesn't actually exist yet.`,
        severity: "low",
        score: 8.0,
      },
    ],
    auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
    frameworks: [
      {
        label: "MITRE ATT&CK",
        key: "mitre_attack",
        controls: [
          { id: "T1566", name: `Phishing` },
        ],
      },
      {
        label: "NIST CSF",
        key: "nist_csf",
        controls: [
          { id: "DE.AE-02", name: `Detected events are analyzed to understand attack targets and methods` },
        ],
      },
      {
        label: "ISO 27001",
        key: "iso_27001",
        controls: [
          { id: "A.5.7", name: `Threat intelligence` },
        ],
      },
      {
        label: "SOC 2",
        key: "soc2",
        controls: [
          { id: "CC6.6", name: `The entity implements controls to protect against external threats` },
        ],
      },
    ],
    narrative: `# Phishing Risk Assessment

**Verdict: LOW RISK** (8/100)

## Analysis

**Mitigating Factors:**
- Generic, work-appropriate content with no suspicious requests
- Natural tone consistent with internal team communication
- No links, attachments, or credential solicitations
- No urgency, threats, or unusual demands

**Caution Flag:**
- **First contact from this sender** — The primary risk indicator. While the email itself is benign, the combination of a new sender and claims of shared team context warrants verification if you're uncertain about this person's role.

## Recommendation

**Action:** Low vigilance required, but verify if unfamiliar:
- If "Sarah Chen" is a known colleague at your organization, this is routine and safe to engage with
- If you don't recognize this person or the referenced "planning sync," respond cautiously — ask your manager or check the company directory before replying or sharing information
- Look for organizational context clues (email domain legitimacy, whether the meeting actually occurred)

**No immediate threat indicators present.** This appears to be legitimate internal communication.`,
    analystModel: "claude-haiku-4-5",
  },
];
