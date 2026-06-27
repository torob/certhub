import { defineConfig } from "vite";

export default defineConfig({
  build: {
    sourcemap: false,
    outDir: "../dist/web",
    emptyOutDir: true
  }
});
