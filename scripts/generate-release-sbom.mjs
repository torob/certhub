#!/usr/bin/env node
import childProcess from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const goSum = fs.readFileSync("go.sum", "utf8").trim().split(/\n+/).filter(Boolean);
const packageLock = JSON.parse(fs.readFileSync("web/package-lock.json", "utf8"));
const archiveRoot = process.argv[2];

const goModules = childProcess
  .execFileSync(process.env.GO_BIN || "go", ["list", "-mod=readonly", "-m", "all"], {
    encoding: "utf8",
    env: {
      ...process.env,
      GOCACHE: process.env.GOCACHE || `${process.env.HOME}/.cache/go-build`,
      GOPATH: process.env.GOPATH || `${process.env.HOME}/go`,
      GOMODCACHE: process.env.GOMODCACHE || `${process.env.HOME}/go/pkg/mod`,
      GOPROXY: process.env.GOPROXY || "https://proxy.golang.org,direct"
    }
  })
  .trim()
  .split(/\n+/)
  .filter(Boolean)
  .map((line) => {
    const [module, version = ""] = line.split(/\s+/);
    return { module, version };
  });

const goChecksums = goSum.map((line) => {
  const [module, version, sum] = line.split(/\s+/);
  const goMod = version.endsWith("/go.mod");
  return { module, version: goMod ? version.replace(/\/go\.mod$/, "") : version, type: goMod ? "go.mod" : "module", sum };
});

const npmPackages = Object.entries(packageLock.packages || {})
  .filter(([path]) => path !== "")
  .map(([path, pkg]) => ({
    path,
    name: path.replace(/^node_modules\//, ""),
    version: pkg.version || "",
    license: pkg.license || "",
    resolved: pkg.resolved || "",
    integrity: pkg.integrity || ""
  }));

function artifactType(rel) {
  if (rel.startsWith("bin/")) return "binary";
  if (rel.startsWith("deploy/helm/")) return "helm";
  if (rel.startsWith("deploy/docker/")) return "dockerfile";
  if (rel.startsWith("deploy/systemd/")) return "systemd";
  if (rel.startsWith("config/examples/")) return "config";
  if (rel.startsWith("migrations/")) return "migration";
  if (rel.startsWith("api/")) return "openapi";
  if (rel.startsWith("specs/")) return "spec";
  if (rel.startsWith("manifests/")) return "manifest";
  return "file";
}

function listArtifacts(root) {
  if (!root) return [{ path: "certhub-release.tar.gz", type: "archive" }];
  const out = [{ path: "certhub-release.tar.gz", type: "archive" }];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const rel = path.relative(root, full).split(path.sep).join("/");
      out.push({ path: rel, type: artifactType(rel) });
    }
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

const sbom = {
  schema: "certhub-release-sbom-v1",
  generated_at: process.env.BUILD_TIMESTAMP || new Date(Number(process.env.SOURCE_DATE_EPOCH || "0") * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"),
  components: {
    go_modules: goModules,
    go_checksums: goChecksums,
    npm_packages: npmPackages
  },
  artifacts: listArtifacts(archiveRoot)
};

process.stdout.write(`${JSON.stringify(sbom, null, 2)}\n`);
