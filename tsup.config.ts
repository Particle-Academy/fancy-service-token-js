import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  sourcemap: true,
  clean: true,
  // node:crypto and node:async_hooks: a server-side package by definition.
  platform: "node",
  treeshake: true,
});
