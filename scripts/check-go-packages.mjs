#!/usr/bin/env node
import fs from "node:fs";

const [packagesPath] = process.argv.slice(2);
if (!packagesPath) {
  console.error("usage: check-go-packages.mjs <go-list-packages-json>");
  process.exit(2);
}

const failures = [];
const content = fs.readFileSync(packagesPath, "utf8").trim();
const packages = content ? content.split(/\n(?=\{)/).map((chunk) => JSON.parse(chunk)) : [];

for (const pkg of packages) {
  const cgoFiles = [
    ...(pkg.CgoFiles || []),
    ...(pkg.CFiles || []),
    ...(pkg.CXXFiles || []),
    ...(pkg.MFiles || [])
  ];
  if (cgoFiles.length > 0) {
    failures.push(`${pkg.ImportPath} includes native/cgo files: ${cgoFiles.join(", ")}`);
  }
}

if (failures.length > 0) {
  console.error("Go native dependency policy failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Go native dependency policy passed: ${packages.length} package(s).`);
