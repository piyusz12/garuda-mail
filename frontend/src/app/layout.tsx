import 'reflect-metadata';
import type { Metadata, Viewport } from "next";
import "./globals.css";
import AuthProvider from "@/components/providers/AuthProvider";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  themeColor: "#0B0D10",
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
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />
      </head>
      <body className="antialiased" suppressHydrationWarning>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
