import 'reflect-metadata';
import type { Metadata, Viewport } from "next";
import "./globals.css";
import AuthProvider from "@/components/providers/AuthProvider";
import ThemeProvider from "@/components/providers/ThemeProvider";

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
  title: "Garuda Mail — Cryptographic Forensics & Security Intelligence",
  description: "Enterprise-grade passive email cryptographic forensics and security analysis platform. Analyze PCAP captures, evaluate TLS handshakes, X.509 certificates, and identify security weaknesses.",
  keywords: ["email security", "cryptographic forensics", "TLS analysis", "PCAP", "certificate analysis", "SMTP security"],
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
          <AuthProvider>{children}</AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
