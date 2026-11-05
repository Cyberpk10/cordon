import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Cordon: AI-Native Defensive Security Platform",
    short_name: "Cordon",
    description:
      "Real-time phishing analysis, autonomous containment, and audit-ready compliance evidence.",
    start_url: "/",
    display: "standalone",
    background_color: "#070b16",
    theme_color: "#070b16",
    icons: [
      {
        src: "/icon-512.png",
        sizes: "512x512",
        type: "image/png",
      },
    ],
  };
}
