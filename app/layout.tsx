import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Cordon: AI-Native Defensive Security Platform",
  description:
    "Cordon analyzes every email in real time, contains threats autonomously within guardrails you control, and turns every detection into audit-ready evidence mapped to MITRE ATT&CK, NIST CSF, ISO 27001, and SOC 2.",
  icons: {
    icon: [{ url: "/favicon-32.png", sizes: "32x32", type: "image/png" }],
    apple: [
      { url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" },
    ],
  },
  manifest: "/manifest.webmanifest",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${inter.variable} h-full antialiased`}>
      <body className="min-h-full flex flex-col bg-navy-950 text-slate-200">
        {children}
      </body>
    </html>
  );
}
