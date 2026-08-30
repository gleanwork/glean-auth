import { defineConfig } from "tsup";

const shared = {
  format: ["esm"] as const,
  sourcemap: true,
  target: "node22" as const,
  outDir: "dist",
};

export default defineConfig([
  {
    ...shared,
    entry: { index: "src/index.ts" },
    dts: true,
    clean: true,
  },
  {
    ...shared,
    entry: { cli: "src/cli.ts" },
    dts: false,
    clean: false,
  },
]);
