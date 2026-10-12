import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(({ mode }) => {
  // Devtools builds (`--mode devtools`) add the profiler window; others leave it out.
  const devtools = mode === "devtools";
  return {
    plugins: [solid(), tailwindcss()],
    define: { __GHOST_DEVTOOLS__: JSON.stringify(devtools) },
    build: {
      rollupOptions: {
        input: devtools ? { main: "index.html", profiler: "profiler.html" } : { main: "index.html" },
      },
    },
    clearScreen: false,
    server: {
      port: 1420,
      strictPort: true,
      host: host || false,
      hmr: host
        ? { protocol: "ws", host, port: 1421 }
        : undefined,
      watch: {
        ignored: ["**/src-tauri/**"],
      },
    },
    test: {
      // Tauri's IPC mocks live on `window`.
      environment: "happy-dom",
      include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    },
  };
});
