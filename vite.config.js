import { defineConfig } from "vite";
import { crx } from "@crxjs/vite-plugin";
import manifest from "./manifest.json";

export default defineConfig({
  build: {
    emptyOutDir: true,
    outDir: "dist",
  },
  plugins: [crx({ manifest })],
});