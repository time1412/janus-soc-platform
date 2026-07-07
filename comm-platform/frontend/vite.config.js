import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// 개발 서버에서 /api·/ws 를 백엔드(8810)로 프록시. 빌드 결과는 FastAPI가 직접 서빙.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8810",
      "/ws": { target: "ws://localhost:8810", ws: true },
    },
  },
  build: { outDir: "dist" },
});
