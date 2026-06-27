#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const reviewedIgnores = [];
const toolsDir = process.env.CODEX_TOOLS || path.join(os.homedir(), ".tools");

function executable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function resolveNpm() {
  const versionedNpm = path.join(toolsDir, "node", "24.15.0", "bin", "npm");
  const toolsBinNpm = path.join(toolsDir, "bin", "npm");
  if (executable(versionedNpm)) return versionedNpm;
  if (executable(toolsBinNpm)) return toolsBinNpm;
  if (process.env.NPM && executable(process.env.NPM)) return process.env.NPM;
  return "npm";
}

const npmBin = resolveNpm();

function runAudit(args, label) {
  const result = spawnSync(npmBin, ["audit", ...args, "--json", "--registry", "https://registry.npmjs.org"], {
    cwd: "web",
    encoding: "utf8"
  });
  const output = result.stdout || result.stderr || "{}";
  let report;
  try {
    report = JSON.parse(output);
  } catch (error) {
    console.error(`${label} audit did not return JSON`);
    console.error(output);
    process.exit(1);
  }

  const vulnerabilities = Object.values(report.vulnerabilities || {});
  const unignored = vulnerabilities.filter((vulnerability) => {
    return !reviewedIgnores.some((ignore) => {
      const expires = Date.parse(ignore.expires);
      return (
        ignore.component === vulnerability.name &&
        ignore.severity === vulnerability.severity &&
        Number.isFinite(expires) &&
        expires >= Date.now()
      );
    });
  });

  if (unignored.length > 0) {
    console.error(`${label} npm audit failed:`);
    for (const vulnerability of unignored) {
      console.error(`- ${vulnerability.name}: ${vulnerability.severity}, range ${vulnerability.range || "unknown"}`);
    }
    process.exit(1);
  }

  if (result.status !== 0 && vulnerabilities.length === 0) {
    console.error(`${label} npm audit failed without vulnerability details`);
    console.error(output);
    process.exit(result.status || 1);
  }

  console.log(`${label} npm audit passed.`);
}

runAudit(["--omit=dev", "--audit-level=high"], "production");
runAudit(["--audit-level=moderate"], "full");
