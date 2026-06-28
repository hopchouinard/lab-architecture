import { defineConfig } from 'astro/config';
import react from '@astrojs/react';
import mdx from '@astrojs/mdx';

// Static publish site — no SSR, no live data (security posture).
export default defineConfig({
  site: 'https://agentops.patchoutech.com',
  output: 'static',
  integrations: [react(), mdx()],
});
