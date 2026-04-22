import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-bulletproofs/',
  server: {
    port: 5173,
    host: true,
  },
});
