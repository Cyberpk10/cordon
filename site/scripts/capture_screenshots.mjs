// Captures real product screenshots from the live Cordon app for the marketing site.
// Credentials come from env vars only (CORDON_EMAIL / CORDON_PASSWORD) — never hardcode or
// commit them. Run: CORDON_EMAIL=... CORDON_PASSWORD=... node scripts/capture_screenshots.mjs
import { chromium } from "playwright";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(__dirname, "..", "public", "screenshots");
const APP_URL = "https://app.cordoncybersec.us/";

const EMAIL = process.env.CORDON_EMAIL;
const PASSWORD = process.env.CORDON_PASSWORD;

if (!EMAIL || !PASSWORD) {
  console.error(
    "Missing credentials. Run with CORDON_EMAIL=... CORDON_PASSWORD=... node scripts/capture_screenshots.mjs"
  );
  process.exit(1);
}

// Nav tabs and case rows are plain onClick React handlers, not links — a real Playwright
// click() (full event dispatch) works in practice, but this falls back to a synthetic
// click via page.evaluate if the expected content never shows up.
async function clickRobust(locator, { timeout = 5000 } = {}) {
  await locator.scrollIntoViewIfNeeded();
  await locator.click({ timeout }).catch(() => {});
}

async function evalClickFallback(locator) {
  await locator.evaluate((el) => el.click());
}

async function main() {
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
  });
  const page = await context.newPage();

  console.log(`Navigating to ${APP_URL}`);
  await page.goto(APP_URL, { waitUntil: "domcontentloaded" });

  await page.locator('input[type="email"]').fill(EMAIL);
  await page.locator('input[type="password"]').fill(PASSWORD);
  await page.getByRole("button", { name: /^sign in$/i }).click();

  // Dashboard is the default tab after login — wait for its KPI header text.
  await page.getByText("Total Analyzed", { exact: true }).waitFor({ timeout: 20000 });
  // Let the KPI numbers and charts finish rendering after the summary fetch resolves.
  await page.waitForTimeout(1500);

  const dashboardPath = path.join(OUT_DIR, "dashboard.png");
  await page.screenshot({ path: dashboardPath });
  console.log(`Saved ${dashboardPath}`);

  // --- Cases tab ---
  const casesTab = page.getByRole("button", { name: /^cases$/i });
  await clickRobust(casesTab);
  let casesTable = page.locator("table");
  try {
    await casesTable.waitFor({ timeout: 5000 });
  } catch {
    await evalClickFallback(casesTab);
    await casesTable.waitFor({ timeout: 10000 });
  }

  async function captureCase(verdictLabel, outFile) {
    const row = page.locator("tr", { hasText: verdictLabel }).first();
    await row.waitFor({ timeout: 10000 });
    await row.click();

    // Once this click lands, the cases <table> is gone (CaseDetail replaces it) — no
    // point falling back to re-clicking `row`, so just wait longer for the detail view.
    const riskScore = page.getByText(/risk score/i).first();
    await riskScore.waitFor({ timeout: 15000 });
    await page.waitForTimeout(500);

    const outPath = path.join(OUT_DIR, outFile);
    await page.screenshot({ path: outPath });
    console.log(`Saved ${outPath}`);

    await page.getByText(/back to cases/i).click();
    await casesTable.waitFor({ timeout: 10000 });
  }

  await captureCase("Malicious", "analyze-malicious.png");
  await captureCase("Safe", "analyze-safe.png");

  await browser.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
