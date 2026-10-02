import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 4001,
    strictPort: true,
    proxy: {
      "/api": { target: "http://localhost:4001", changeOrigin: false },
    },
  },
});
