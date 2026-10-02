import fs from "node:fs";
import path from "node:path";

const SCREENSHOTS_DIR = path.join(process.cwd(), "public", "screenshots");
const VIDEO_DIR = path.join(process.cwd(), "public", "video");

export type ScreenshotAvailability = {
  analyzeMalicious: boolean;
  analyzeSafe: boolean;
  dashboard: boolean;
  walkthroughVideo: boolean;
};

/**
 * Server-only: checks which real product media has actually been dropped into public/.
 * Called once in app/page.tsx and passed down as props, since client components
 * (ProductTour, the screenshot showcase) can't touch the filesystem themselves. Never
 * fabricate a screenshot or play a broken video — a missing file renders an honest,
 * clearly-labeled placeholder instead.
 */
export function getScreenshotAvailability(): ScreenshotAvailability {
  const exists = (dir: string, name: string) =>
    fs.existsSync(path.join(dir, name));

  return {
    analyzeMalicious: exists(SCREENSHOTS_DIR, "analyze-malicious.png"),
    analyzeSafe: exists(SCREENSHOTS_DIR, "analyze-safe.png"),
    dashboard: exists(SCREENSHOTS_DIR, "dashboard.png"),
    walkthroughVideo: exists(VIDEO_DIR, "cordon-walkthrough-90s.mp4"),
  };
}
