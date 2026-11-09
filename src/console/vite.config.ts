import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath } from 'node:url';

// A single browser origin keeps cookies and Origin/CSRF checks intact. Never rewrite Origin.
const target = process.env.HUKID_CONSOLE_API_TARGET || 'http://127.0.0.1:8080';
const address = new URL(target);
if (address.protocol !== 'http:' || address.hostname !== '127.0.0.1' || address.username || address.password || address.pathname !== '/' || address.search || address.hash) {
  throw new Error('HUKID_CONSOLE_API_TARGET must be a plain IPv4 loopback HTTP origin');
}
const proxy = { '/console/': { target, changeOrigin: false } };
const headers = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };
export default defineConfig({
  plugins: [tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: { proxy, headers },
  preview: { proxy, headers },
});
