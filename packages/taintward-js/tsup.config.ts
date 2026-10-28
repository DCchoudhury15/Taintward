import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/ai-sdk.ts"],
  format: ["esm", "cjs"],
  // tsup sets baseUrl for the declaration build, which TypeScript 6 deprecates.
  dts: { compilerOptions: { ignoreDeprecations: "6.0" } },
  sourcemap: true,
  clean: true,
  target: "node20",
});
