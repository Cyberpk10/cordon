// Trimmed to the essentials so the desktop nav fits on one line. The remaining homepage
// sections (Early Warning, Training, Product Tour, Autonomy) are still reachable by
// scrolling the single page, right after Platform. `route` entries render as next/link;
// the rest are plain hash anchors, as they always were.
export const NAV_LINKS = [
  { label: "Platform", href: "/#platform" },
  { label: "Try It", href: "/#playground" },
  { label: "Why Cordon", href: "/#why-aegis" },
  { label: "Security", href: "/security", route: true },
  { label: "About", href: "/#about-founder", route: true },
] as const;

export const DEMO_MAILTO = "mailto:paakowansah@icloud.com?subject=Cordon%20demo%20request";
