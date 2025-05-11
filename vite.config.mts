import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tsconfigPaths from 'vite-tsconfig-paths'
import tailwindcss from '@tailwindcss/vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tsconfigPaths(), tailwindcss()],
  build: {
    minify: false,
  },
  optimizeDeps: {
    exclude: [
      "@yume-chan/fetch-scrcpy-server", 
      "@yume-chan/scrcpy-decoder-tinyh264"
    ],
    include: [
      "@yume-chan/scrcpy-decoder-tinyh264 > yuv-buffer",
      "@yume-chan/scrcpy-decoder-tinyh264 > yuv-canvas",
    ],
  },
  envPrefix: 'DROIDGROUND'
});
