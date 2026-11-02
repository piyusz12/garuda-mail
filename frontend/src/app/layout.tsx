import 'reflect-metadata';
import type { Metadata, Viewport } from "next";
import "./globals.css";
import AuthProvider from "@/components/providers/AuthProvider";
import ThemeProvider from "@/components/providers/ThemeProvider";
import { AriaLiveProvider } from "@/components/common/AriaLiveAnnouncer";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#F8FAFC" },
    { media: "(prefers-color-scheme: dark)", color: "#0B0D10" },
  ],
  viewportFit: "cover",
};

export const metadata: Metadata = {
  title: "Garuda Mail — Cryptographic Forensics & Deliverability Intelligence",
  description: "Enterprise-grade passive email cryptographic forensics, campaign orchestration, deliverability warming, and security analysis platform.",
  keywords: ["email security", "cryptographic forensics", "campaign orchestration", "deliverability warming", "SPF DKIM DMARC", "RFC 8058", "TLS analysis"],
  manifest: "/manifest.webmanifest",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "Garuda Mail",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="light" suppressHydrationWarning>
      <head>
        {/* Prevent theme flash on load */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var theme = localStorage.getItem('garuda-theme') || 'light';
                  document.documentElement.className = theme;
                  var meta = document.querySelector('meta[name="theme-color"]:not([media])');
                  if (!meta) {
                    meta = document.createElement('meta');
                    meta.setAttribute('name', 'theme-color');
                    document.head.appendChild(meta);
                  }
                  meta.setAttribute('content', theme === 'dark' ? '#080B11' : '#F8FAFC');
                } catch(e) {}
              })();
            `,
          }}
        />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />
      </head>
      <body className="antialiased" suppressHydrationWarning>
        <ThemeProvider>
          <AriaLiveProvider>
            {/* Skip navigation link for keyboard accessibility (WCAG 2.4.1) */}
            <a
              href="#main-content"
              className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-sky-600 focus:text-white focus:rounded-md focus:shadow-xl focus:ring-2 focus:ring-sky-400 focus:outline-none text-sm font-medium transition"
            >
              Skip to main content
            </a>
            <AuthProvider>{children}</AuthProvider>
          </AriaLiveProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
