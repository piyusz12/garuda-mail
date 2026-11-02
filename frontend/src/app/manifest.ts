import type { MetadataRoute } from 'next';

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: 'Garuda Mail — Security Forensics',
    short_name: 'Garuda Mail',
    description: 'Cryptographic Forensics & Security Intelligence Platform',
    start_url: '/inbox',
    display: 'standalone',
    background_color: '#F8FAFC',
    theme_color: '#F8FAFC',
    icons: [
      {
        src: '/favicon.ico',
        sizes: 'any',
        type: 'image/x-icon',
      },
    ],
  };
}
