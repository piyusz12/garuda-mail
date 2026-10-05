import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
	allowedDevOrigins: [
		'localhost',
		'127.0.0.1',
		process.env.LAN_IP || '192.168.1.5',
	],
};

export default nextConfig;
