import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
	async headers() {
		return [
			{
				source: '/(.*)',
				headers: [
					{ key: 'X-Content-Type-Options', value: 'nosniff' },
					{ key: 'X-Frame-Options', value: 'DENY' },
					{ key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
					{ key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
				],
			},
		];
	},
	allowedDevOrigins: [
		'localhost',
		'127.0.0.1',
		process.env.LAN_IP || '192.168.1.5',
	],
};

export default nextConfig;
