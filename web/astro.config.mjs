// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';

// A single static page. The Go binary embeds the build (copied to
// internal/webui/build/site by `make web`) and inlines its CSS and JS: into
// the standalone page served on the API port, and into the router's
// Addons page, which must be a single file.
export default defineConfig({
  output: 'static',
  outDir: '../internal/webui/build/site',
  build: {
    inlineStylesheets: 'always',
    format: 'file',
  },
  vite: {
    // React through Vite's React plugin, not Astro's React integration:
    // the app mounts its React components itself (no Astro islands), and
    // the integration's island runtime would add a second script entry,
    // while the router page needs one inlined script.
    plugins: [tailwindcss(), react()],
    build: {
      // One script file: Go inlines it, so no code splitting.
      assetsInlineLimit: 0,
      rollupOptions: { output: { codeSplitting: false } },
    },
  },
  devToolbar: { enabled: false },
});
