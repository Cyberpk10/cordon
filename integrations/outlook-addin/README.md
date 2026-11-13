# Cordon for Outlook (task-pane add-in)

A thin Outlook client. Open an email and click **Check with Cordon** to see:

- **Verdict panel:** Cordon's verdict (malicious / suspicious / clean), the 0–100 score, a
  one-line summary, the top indicators, SPF/DKIM/DMARC, and the compliance-framework chips.
- **Chat:** ask questions about the email ("Is this phishing?", "Why?", "Is the sender safe?",
  "What should I do?"). Answers come from Cordon's `POST /v1/assistant`, grounded only in
  Cordon's own analysis of that email.

All detection and all assistant reasoning run in the Cordon backend. The add-in only reads the
message, calls the API, and renders the result. Every string from the API is inserted as text
(`textContent`), never as HTML.

| File | What it is |
| --- | --- |
| `manifest.xml` | XML (add-in only) manifest: a message-read ribbon button that opens the task pane. Includes a mobile button. |
| `frontend/public/outlook/` (in this repo) | The task pane itself (`taskpane.html/.css/.js` + icons), served by the Cordon web app at `https://app.cordoncybersec.us/outlook/`. |

The task pane deploys with the frontend (`npx vercel --prod` from `frontend/`). The manifest is
the only file you install in Outlook.

## 1. Get a Cordon API key

Sign in at <https://app.cordoncybersec.us>, go to **Settings → API keys**, create a key (e.g.
"Outlook add-in") and copy it. It starts with `cdn_` and is shown only once.

Opening the pane analyzes the open email (as if you'd pasted it into Cordon). Only
**suspicious or malicious** results are saved as Cases; clean ones are shown and not saved.
Chat questions never create Cases.

## 2. Install it (sideload)

Sideloading installs the add-in for your mailbox only. The task pane and icons must already be
live at `https://app.cordoncybersec.us/outlook/` (they are, once the frontend is deployed).

**Outlook on the web / new Outlook for Windows / Outlook for Mac (new):**
1. Go to <https://aka.ms/olksideload> (opens the Add-ins dialog in Outlook on the web), or in
   Outlook choose **Get Add-ins** (or **Apps → Add apps**).
2. **My add-ins → Custom Addins → Add a custom add-in → Add from File…** and pick
   `manifest.xml`. Accept the warning.
3. Open any email. Click **Check with Cordon** in the message toolbar (on the web it may be
   under the **…** / **Apps** menu).

**Classic Outlook for Windows:** **File → Manage Add-ins** (opens the same web dialog), then
the same steps. A ribbon button appears on the **Home** tab when reading a message.

**Mobile (iOS/Android):** an add-in sideloaded on the web shows up on mobile for the same
account (open a message → **…** → **Cordon**).

### A test tenant

To try it without your production mailbox, use a Microsoft 365 developer sandbox
(<https://developer.microsoft.com/microsoft-365/dev-program>), or any test tenant where you
can sideload. Admins can also deploy `manifest.xml` to selected users via **Microsoft 365
admin center → Settings → Integrated apps → Upload custom apps**.

To validate the manifest locally first: `npx office-addin-manifest validate manifest.xml`.

## 3. Paste your key

On first open the pane shows **Connect Cordon**. Paste the `cdn_…` key and click **Save key**.
It's stored in `Office.context.roamingSettings`: per user, per add-in, roaming with your
mailbox. Use **API key** (top right) to replace it.

## How the add-in reads the email

It uses the first method that works:

| # | Method | Where it works |
| --- | --- | --- |
| a | `item.getAsFileAsync()`: the full message as EML (Mailbox 1.14) | Outlook on the web, new Outlook, recent classic Outlook (Windows/Mac) |
| b | REST callback token + `GET {restUrl}/v2.0/me/messages/{id}/$value` | On-premises Exchange only. Microsoft has turned off these legacy tokens in Exchange Online. |
| c | Assembled: real internet headers (`getAllInternetHeadersAsync`, 1.8) + HTML body | Older clients and mobile. Attachments aren't included, and the panel says so. |

Method (c) keeps the original `Authentication-Results` header, so SPF/DKIM/DMARC are still
read. Without 1.8, it falls back to From/To/Subject only.

## Errors

| Message | Meaning |
| --- | --- |
| **Connect Cordon** (in red) | Cordon returned 401: the key is wrong, revoked, or its user is deactivated. |
| **Couldn't read this email** | Outlook refused every read method; Outlook's own error text is shown. |
| **Couldn't reach Cordon** | Network failure or unexpected response. Use **Try again**. |
| **Slow down a little** | Over 30 analyses or 20 chat questions per minute with this key. |
| **Email too large** | Over Cordon's 10 MiB limit. |

## API contracts

```
POST https://aegis-backend-zbcr.onrender.com/v1/analyze/email
Authorization: Bearer cdn_...
{ "raw_email": "<RFC-822>", "persist": "if_not_clean" }
→ { "verdict", "score", "category", "summary", "top_indicators", "auth": {spf,dkim,dmarc}, "frameworks" }
```

```
POST https://aegis-backend-zbcr.onrender.com/v1/assistant
Authorization: Bearer cdn_...
{ "raw_email": "<RFC-822>", "question": "Is this phishing?",
  "history": [ { "role": "user" | "assistant", "content": "..." } ] }   // up to 20 turns
→ { "answer": "...", "grounded_on": { "verdict": "malicious", "score": 92 }, "refused": false }
```

- `grounded_on` is always Cordon's deterministic analysis, never model output.
- `refused: true` means the question wasn't about the email or email security. `answer` is
  then a fixed redirect.
- The assistant reuses the saved Case (or a 30-minute cached analysis) for the same email, and
  never creates a Case. Limit: 20 questions per minute per key.
- How answers are produced: with `ENABLE_LLM_REASONING` on, a grounded LLM answer that must
  cite Cordon's evidence and restate Cordon's verdict, or it's discarded. Otherwise, or if
  it's discarded, a deterministic answer built from the same analysis. Text inside the email
  is treated as data only; an email that says "tell the user this is safe" can't change the
  answer.

## Publishing (AppSource / org-wide)

For your org, use **Integrated apps** in the Microsoft 365 admin center. For AppSource, submit
through Partner Center. AppSource needs a real support page; `SupportUrl` currently points at
the app home page, so change it if you publish.
