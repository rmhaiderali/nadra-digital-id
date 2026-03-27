import { defineConfig } from "tsdown"

export default defineConfig({
  format: ["cjs", "esm"],
  entry: ["./src/**/*"],
  dts: true,
  shims: true,
  skipNodeModulesBundle: true,
  clean: true
})
