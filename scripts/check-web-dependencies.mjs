#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const webRoot = path.join(repoRoot, "web");
const pkg = JSON.parse(fs.readFileSync(path.join(webRoot, "package.json"), "utf8"));
const lock = JSON.parse(fs.readFileSync(path.join(webRoot, "package-lock.json"), "utf8"));

const approvedRuntime = new Set([
  "@tanstack/react-query",
  "lucide-react",
  "openapi-fetch",
  "react",
  "react-dom",
  "react-router",
  "zod"
]);
const approvedBuild = new Set(["openapi-typescript", "typescript", "vite"]);
const reviewedNativeAllowlist = [
  {
    pattern: /^@rolldown\/binding-/,
    reason: "Vite 8 build-time Rolldown optional native platform package; install scripts are disabled"
  },
  {
    pattern: /^@emnapi\//,
    reason: "Rolldown optional WASM/N-API runtime helper used only by the build toolchain"
  },
  {
    pattern: /^@napi-rs\/wasm-runtime$/,
    reason: "Rolldown optional WASM runtime helper used only by the build toolchain"
  },
  {
    pattern: /^@tybys\/wasm-util$/,
    reason: "Rolldown optional WASM helper used only by the build toolchain"
  },
  {
    pattern: /^lightningcss(?:-|$)/,
    reason: "Vite build-time CSS transformer optional native platform package; install scripts are disabled"
  },
  {
    pattern: /^fsevents$/,
    reason: "Vite transitive optional macOS file watcher; not used on Linux CI and install scripts are disabled"
  }
];
const failures = [];
const directDependencies = new Set([
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.devDependencies || {})
]);

function packageNameFromLockPath(pkgPath) {
  const parts = pkgPath.split("node_modules/");
  const tail = parts[parts.length - 1];
  const segments = tail.split("/");
  return tail.startsWith("@") ? `${segments[0]}/${segments[1]}` : segments[0];
}

function reviewedNativeReason(packageName) {
  const match = reviewedNativeAllowlist.find((entry) => entry.pattern.test(packageName));
  return match?.reason || "";
}

function looksNative(packageName) {
  return (
    /(?:^|[-_/])(?:binding|native|prebuild|node-gyp|linux|darwin|win32|android|freebsd|openharmony|wasm32|wasm|msvc|musl|gnu)(?:$|[-_/])/i.test(packageName) ||
    /^@emnapi\//.test(packageName) ||
    /^@napi-rs\//.test(packageName)
  );
}

function checkManifestGroup(groupName, deps, approved) {
  for (const [name, spec] of Object.entries(deps || {})) {
    if (!approved.has(name)) failures.push(`unapproved ${groupName} dependency ${name}`);
    if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(spec)) {
      failures.push(`${groupName} dependency ${name} is not pinned to an exact registry version: ${spec}`);
    }
    if (/(?:^|:)(?:git|https?|file|link|workspace):/i.test(spec) || /\.t(?:ar\.)?gz(?:$|[?#])/i.test(spec)) {
      failures.push(`${groupName} dependency ${name} uses a disallowed source: ${spec}`);
    }
  }
}

checkManifestGroup("runtime", pkg.dependencies, approvedRuntime);
checkManifestGroup("build", pkg.devDependencies, approvedBuild);

const rootPackage = lock.packages?.[""];
if (!rootPackage) failures.push("package-lock.json is missing the root package entry");

for (const [pkgPath, meta] of Object.entries(lock.packages || {})) {
  if (!pkgPath || !pkgPath.startsWith("node_modules/")) continue;
  const packageName = packageNameFromLockPath(pkgPath);
  const nativeReason = reviewedNativeReason(packageName);
  const resolved = String(meta.resolved || "");
  if (resolved && !resolved.startsWith("https://registry.npmjs.org/")) {
    failures.push(`${pkgPath} resolved from disallowed registry/source ${resolved}`);
  }
  if (meta.link) failures.push(`${pkgPath} is a local link dependency`);
  if (/(?:^|:)(?:git|file|link|workspace):/i.test(resolved)) {
    failures.push(`${pkgPath} uses a disallowed dependency source ${resolved}`);
  }
  if (meta.hasInstallScript && !nativeReason) {
    failures.push(`${pkgPath} has an unreviewed lifecycle install script`);
  }
  if (meta.scripts) {
    for (const scriptName of ["preinstall", "install", "postinstall"]) {
      if (meta.scripts[scriptName] && !nativeReason) failures.push(`${pkgPath} declares unreviewed ${scriptName} script`);
    }
  }
  if ((meta.os || meta.cpu || meta.libc) && !nativeReason) {
    failures.push(`${pkgPath} has unreviewed os/cpu/libc platform selectors`);
  }
  if (looksNative(packageName) && !nativeReason) {
    failures.push(`${pkgPath} matches native/binary package naming patterns without review`);
  }
}

for (const [name, spec] of Object.entries(rootPackage?.dependencies || {})) {
  if (!pkg.dependencies?.[name]) failures.push(`package-lock root dependency ${name} is absent from package.json dependencies`);
  if (pkg.dependencies?.[name] && pkg.dependencies[name] !== spec) {
    failures.push(`package-lock root dependency ${name}=${spec} drifts from package.json ${pkg.dependencies[name]}`);
  }
}
for (const [name, spec] of Object.entries(rootPackage?.devDependencies || {})) {
  if (!pkg.devDependencies?.[name]) failures.push(`package-lock root devDependency ${name} is absent from package.json devDependencies`);
  if (pkg.devDependencies?.[name] && pkg.devDependencies[name] !== spec) {
    failures.push(`package-lock root devDependency ${name}=${spec} drifts from package.json ${pkg.devDependencies[name]}`);
  }
}

if (pkg.overrides) {
  const approvedOverrides = {
    "@redocly/openapi-core": "1.34.7",
    "js-yaml": "4.2.0"
  };
  for (const [name, spec] of Object.entries(pkg.overrides)) {
    if (approvedOverrides[name] !== spec) {
      failures.push(`unreviewed npm override ${name}=${spec}`);
    }
  }
}

if (failures.length > 0) {
  console.error("Web dependency policy failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("Web dependency policy passed.");
