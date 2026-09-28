import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Garuda Mail — Cryptographic Forensics & Security Intelligence",
  description: "Enterprise-grade passive email cryptographic forensics and security analysis platform. Analyze PCAP captures, evaluate TLS handshakes, X.509 certificates, and identify security weaknesses.",
  keywords: ["email security", "cryptographic forensics", "TLS analysis", "PCAP", "certificate analysis", "SMTP security"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />
      </head>
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
