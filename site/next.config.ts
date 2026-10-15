import type { NextConfig } from "next";

// Security hardening pass — the same baseline browser-enforced headers the backend
// (aegis-backend) sends on every response via app.core.security_headers, applied here via
// Next.js's own headers() config so Vercel sets them at the edge for every route on this
// site, not just API responses.
const securityHeaders = [
  // 2 years, applies to subdomains, eligible for browser preload lists. Harmless to send
  // even over a local http:// dev request — browsers only honor HSTS on a response actually
  // received over HTTPS.
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
];

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
