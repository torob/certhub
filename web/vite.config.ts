import { defineConfig } from "vite";

export default defineConfig({
  build: {
    sourcemap: false,
    outDir: "../dist/web",
    emptyOutDir: true,
    rolldownOptions: {
      onLog(level, log, defaultHandler) {
        // React libraries ship "use client" for server components; it has no effect in this browser-only app.
        if (log.code === "MODULE_LEVEL_DIRECTIVE" && log.message.includes('"use client"')) {
          return;
        }
        defaultHandler(level, log);
      }
    }
  }
});
