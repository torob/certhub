#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const lock = JSON.parse(fs.readFileSync(path.join("web", "package-lock.json"), "utf8"));
const allowedLicenses = new Set([
  "0BSD",
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "CC0-1.0",
  "ISC",
  "MIT",
  "MPL-2.0",
  "Python-2.0"
]);
const reviewedLicenseExpressions = new Set(["(MIT OR CC0-1.0)"]);
const failures = [];
const licenses = new Map();

function isAllowedExpression(license) {
  if (allowedLicenses.has(license) || reviewedLicenseExpressions.has(license)) return true;
  const orParts = license.replace(/[()]/g, "").split(/\s+OR\s+/);
  return orParts.length > 1 && orParts.every((part) => allowedLicenses.has(part.trim()));
}

for (const [pkgPath, meta] of Object.entries(lock.packages || {})) {
  if (!pkgPath.startsWith("node_modules/")) continue;
  const license = String(meta.license || "");
  licenses.set(license || "<missing>", (licenses.get(license || "<missing>") || 0) + 1);
  if (!license) {
    failures.push(`${pkgPath} is missing license metadata`);
    continue;
  }
  if (!isAllowedExpression(license)) {
    failures.push(`${pkgPath} has unreviewed license ${license}`);
  }
}

if (failures.length > 0) {
  console.error("Web license policy failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

const summary = [...licenses.entries()]
  .sort(([left], [right]) => left.localeCompare(right))
  .map(([license, count]) => `${license}:${count}`)
  .join(", ");
console.log(`Web license policy passed: ${summary}`);
