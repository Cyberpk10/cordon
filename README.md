# Aegis marketing site

A single-page marketing site for Aegis — an AI-native defensive security platform (phishing
analysis, intrusion & exfiltration detection, autonomous response, and compliance evidence).
Built with Next.js (App Router), TypeScript, and Tailwind CSS. No CMS, no backend, no
environment variables — every "product mock" on the page is built with Tailwind, not real
screenshots or live data.

## Development

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

Before shipping any change, confirm a clean production build:

```bash
npm run build
```

## Structure

- `app/layout.tsx` — global metadata, font, and page shell.
- `app/page.tsx` — assembles all landing-page sections in order.
- `components/` — one component per section (`Nav`, `Hero`, `StatStrip`, `PlatformCards`,
  `ProductTour`, `WhyAegis`, `AutonomyBand`, `FinalCta`, `Footer`). `ProductTour` is the only
  client component (`"use client"`) — it drives the 5-step interactive tour with `useState`.
- `app/globals.css` — Tailwind import plus the brand palette (`navy`, `navy-800`, `navy-950`,
  `brand-blue`, `brand-purple`) defined as Tailwind v4 theme tokens, used as e.g. `bg-navy` /
  `text-brand-blue` anywhere in the components.

## Deploying to Vercel

No environment variables or extra configuration are required — this is a static Next.js app.

**Option A — Vercel CLI:**

```bash
npx vercel
```

Follow the prompts (log in, link/create a project, deploy). Run `npx vercel --prod` for a
production deploy once you're happy with a preview.

**Option B — Git integration:**

1. Push this repo to GitHub.
2. Go to [vercel.com/new](https://vercel.com/new) and import the repository.
3. Vercel auto-detects Next.js — accept the defaults and deploy.

## Contact

Paa Ekow Ansah (PK) · paakowansah@icloud.com
