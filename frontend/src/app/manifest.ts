import type { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'Garuda Mail — Security Forensics',
    short_name: 'Garuda Mail',
    description: 'Cryptographic Forensics & Security Intelligence Platform',
    start_url: '/inbox',
    display: 'standalone',
    background_color: '#0B0D10',
    theme_color: '#0B0D10',
    icons: [
      {
        src: '/favicon.ico',
        sizes: 'any',
        type: 'image/x-icon',
      },
    ],
  };
}
