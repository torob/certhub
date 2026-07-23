#!/usr/bin/env node
import fs from "node:fs";

const args = parseArgs(process.argv.slice(2));
if (!args.goModPath || !args.moduleGraphPath || !args.packageGraphPath) {
  console.error("usage: check-go-modules.mjs --go-mod <go-mod-json> --module-graph <go-list-m-json> --package-graph <go-list-packages-json>");
  process.exit(2);
}

const goMod = JSON.parse(fs.readFileSync(args.goModPath, "utf8"));
const moduleGraph = parseJSONStream(args.moduleGraphPath);
const packages = parseJSONStream(args.packageGraphPath);
const goSumEntries = parseGoSum("go.sum");
const mainModulePath = moduleGraph.find((mod) => mod.Main)?.Path || goMod.Module?.Path;
const moduleGraphByPath = new Map(moduleGraph.map((mod) => [mod.Path, mod]));
const currentModuleVersionKeys = new Set(
  moduleGraph
    .filter((mod) => !mod.Main)
    .map((mod) => moduleVersionKey(mod.Path, mod.Version || ""))
);
const compiledModules = usedModules(packages);
const compiledModulePaths = new Set(compiledModules.map((mod) => mod.Path));

const approvedDirectRequires = versionMap({
  "github.com/jackc/pgx/v5": "v5.10.0",
  "github.com/pressly/goose/v3": "v3.27.1",
  "github.com/skip2/go-qrcode": "v0.0.0-20200617195104-da1b6568686e",
  "github.com/spf13/cobra": "v1.10.2",
  "go.yaml.in/yaml/v4": "v4.0.0-rc.6",
  "golang.org/x/crypto": "v0.53.0",
  "golang.org/x/net": "v0.55.0"
});

const approvedCompiledModules = versionMap({
  [mainModulePath]: "",
  "github.com/jackc/pgpassfile": "v1.0.0",
  "github.com/jackc/pgservicefile": "v0.0.0-20240606120523-5a60cdf6a761",
  "github.com/jackc/pgx/v5": "v5.10.0",
  "github.com/jackc/puddle/v2": "v2.2.2",
  "github.com/mfridman/interpolate": "v0.0.2",
  "github.com/pressly/goose/v3": "v3.27.1",
  "github.com/sethvargo/go-retry": "v0.3.0",
  "github.com/skip2/go-qrcode": "v0.0.0-20200617195104-da1b6568686e",
  "github.com/spf13/cobra": "v1.10.2",
  "github.com/spf13/pflag": "v1.0.9",
  "go.uber.org/multierr": "v1.11.0",
  "go.yaml.in/yaml/v4": "v4.0.0-rc.6",
  "golang.org/x/crypto": "v0.53.0",
  "golang.org/x/net": "v0.55.0",
  "golang.org/x/sync": "v0.21.0",
  "golang.org/x/sys": "v0.46.0",
  "golang.org/x/text": "v0.39.0"
});

// Reviewed unused modules retained by optional dependency graphs, such as
// goose database-driver/test dependencies and cobra documentation helpers. They
// are allowed only while absent from the compiled Certhub package graph.
const reviewedUnusedGooseModules = versionMap({
  "filippo.io/edwards25519": "v1.2.0",
  "github.com/ClickHouse/ch-go": "v0.71.0",
  "github.com/ClickHouse/clickhouse-go/v2": "v2.45.0",
  "github.com/Microsoft/go-winio": "v0.6.2",
  "github.com/andybalholm/brotli": "v1.2.1",
  "github.com/antlr4-go/antlr/v4": "v4.13.1",
  "github.com/cespare/xxhash/v2": "v2.3.0",
  "github.com/coder/websocket": "v1.8.14",
  "github.com/containerd/errdefs": "v1.0.0",
  "github.com/containerd/errdefs/pkg": "v0.3.0",
  "github.com/cpuguy83/go-md2man/v2": "v2.0.6",
  "github.com/davecgh/go-spew": "v1.1.1",
  "github.com/distribution/reference": "v0.6.0",
  "github.com/docker/go-connections": "v0.7.0",
  "github.com/docker/go-units": "v0.5.0",
  "github.com/dustin/go-humanize": "v1.0.1",
  "github.com/elastic/go-sysinfo": "v1.15.4",
  "github.com/elastic/go-windows": "v1.0.2",
  "github.com/felixge/httpsnoop": "v1.0.4",
  "github.com/go-faster/city": "v1.0.1",
  "github.com/go-faster/errors": "v0.7.1",
  "github.com/go-logr/logr": "v1.4.3",
  "github.com/go-logr/stdr": "v1.2.2",
  "github.com/go-sql-driver/mysql": "v1.9.3",
  "github.com/golang-jwt/jwt/v4": "v4.5.2",
  "github.com/golang-sql/civil": "v0.0.0-20220223132316-b832511892a9",
  "github.com/golang-sql/sqlexp": "v0.1.0",
  "github.com/google/uuid": "v1.6.0",
  "github.com/inconshreveable/mousetrap": "v1.1.0",
  "github.com/joho/godotenv": "v1.5.1",
  "github.com/jonboulle/clockwork": "v0.5.0",
  "github.com/klauspost/compress": "v1.18.5",
  "github.com/kr/pretty": "v0.3.0",
  "github.com/mattn/go-isatty": "v0.0.21",
  "github.com/mfridman/xflag": "v0.1.0",
  "github.com/microsoft/go-mssqldb": "v1.9.8",
  "github.com/moby/docker-image-spec": "v1.3.1",
  "github.com/moby/moby/api": "v1.54.2",
  "github.com/moby/moby/client": "v0.4.1",
  "github.com/ncruces/go-strftime": "v1.0.0",
  "github.com/opencontainers/go-digest": "v1.0.0",
  "github.com/opencontainers/image-spec": "v1.1.1",
  "github.com/paulmach/orb": "v0.13.0",
  "github.com/pierrec/lz4/v4": "v4.1.26",
  "github.com/pmezard/go-difflib": "v1.0.0",
  "github.com/prometheus/procfs": "v0.20.1",
  "github.com/remyoudompheng/bigfft": "v0.0.0-20230129092748-24d4a6f8daec",
  "github.com/russross/blackfriday/v2": "v2.1.0",
  "github.com/segmentio/asm": "v1.2.1",
  "github.com/shopspring/decimal": "v1.4.0",
  "github.com/stretchr/objx": "v0.1.0",
  "github.com/stretchr/testify": "v1.11.1",
  "github.com/tursodatabase/libsql-client-go": "v0.0.0-20251219100830-236aa1ff8acc",
  "github.com/vertica/vertica-sql-go": "v1.3.6",
  "github.com/ydb-platform/ydb-go-genproto": "v0.0.0-20260311095541-ebbf792c1180",
  "github.com/ydb-platform/ydb-go-sdk/v3": "v3.135.0",
  "github.com/ziutek/mymysql": "v1.5.4",
  "go.opentelemetry.io/auto/sdk": "v1.2.1",
  "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp": "v0.68.0",
  "go.opentelemetry.io/otel": "v1.43.0",
  "go.opentelemetry.io/otel/metric": "v1.43.0",
  "go.opentelemetry.io/otel/trace": "v1.43.0",
  "go.yaml.in/yaml/v3": "v3.0.4",
  "golang.org/x/exp": "v0.0.0-20260410095643-746e56fc9e2f",
  "golang.org/x/mod": "v0.37.0",
  "golang.org/x/term": "v0.44.0",
  "golang.org/x/tools": "v0.47.0",
  "google.golang.org/genproto/googleapis/rpc": "v0.0.0-20260420184626-e10c466a9529",
  "google.golang.org/grpc": "v1.80.0",
  "google.golang.org/protobuf": "v1.36.11",
  "gopkg.in/check.v1": "v1.0.0-20201130134442-10cb98267c6c",
  "gopkg.in/yaml.v3": "v3.0.1",
  "howett.net/plist": "v1.0.1",
  "modernc.org/libc": "v1.72.1",
  "modernc.org/mathutil": "v1.7.1",
  "modernc.org/memory": "v1.11.0",
  "modernc.org/sqlite": "v1.49.1"
});

// Go 1.26.5 tidy retains these historical go.mod checksums for module graph
// resolution, even though the selected module versions above are newer.
const reviewedChecksumOnlyGoModSums = moduleVersionSet([
  ["github.com/davecgh/go-spew", "v1.1.0"],
  ["github.com/stretchr/testify", "v1.3.0"],
  ["github.com/stretchr/testify", "v1.7.0"],
  ["gopkg.in/check.v1", "v0.0.0-20161208181325-20d25e280405"],
  ["gopkg.in/yaml.v3", "v3.0.0-20200313102051-9f266ea9e77c"]
]);

const failures = [];

checkGoModDirectRequires();
checkCompiledPackageGraph();
checkModuleGraphExceptions();
checkGoSumPolicy();

if (failures.length > 0) {
  console.error("Go dependency policy failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Go direct require policy passed: ${directRequires().length} direct require(s).`);
console.log(`Go compiled package graph policy passed: ${compiledModules.length} module(s).`);
console.log(`Go unused module graph policy passed: ${reviewedUnusedGraphModules().length} reviewed optional exception(s).`);
console.log(`Go checksum policy passed: ${goSumEntries.length} go.sum entr${goSumEntries.length === 1 ? "y" : "ies"}, ${reviewedChecksumOnlyGoModSums.size} reviewed checksum-only exception(s).`);

function checkGoModDirectRequires() {
  for (const replacement of goMod.Replace || []) {
    failures.push(`go.mod uses replace directive for ${replacement.Old?.Path || "unknown module"}`);
  }
  for (const excluded of goMod.Exclude || []) {
    failures.push(`go.mod uses exclude directive for ${excluded.Path || "unknown module"} ${excluded.Version || ""}`.trim());
  }

  for (const requirement of directRequires()) {
    const path = requirement.Path;
    const version = requirement.Version || "";
    if (!approvedDirectRequires.has(path)) {
      failures.push(`unapproved direct go.mod require ${path} ${version}`);
      continue;
    }
    if (approvedDirectRequires.get(path) !== version) {
      failures.push(`direct go.mod require ${path} has unreviewed version ${version}; expected ${approvedDirectRequires.get(path)}`);
    }
    if (!compiledModulePaths.has(path)) {
      failures.push(`direct go.mod require ${path} ${version} is dormant; it is not present in the compiled package graph`);
    }
    if (path === "gopkg.in/yaml.v3") {
      failures.push("gopkg.in/yaml.v3 must not be a direct go.mod requirement");
    }
    checkUnsupportedSource({ Path: path, Version: version }, "direct go.mod require");
    checkModuleMetadata(moduleGraphByPath.get(path) || { Path: path, Version: version }, "direct go.mod require");
  }
}

function checkCompiledPackageGraph() {
  for (const mod of compiledModules) {
    if (!approvedCompiledModules.has(mod.Path)) {
      failures.push(`unapproved compiled Go module ${mod.Path} ${mod.Version || ""}`.trim());
      continue;
    }
    if (approvedCompiledModules.get(mod.Path) !== (mod.Version || "")) {
      failures.push(`compiled Go module ${mod.Path} has unreviewed version ${mod.Version || ""}; expected ${approvedCompiledModules.get(mod.Path)}`);
    }
    if (mod.Path === "gopkg.in/yaml.v3") {
      failures.push("gopkg.in/yaml.v3 must not be present in the compiled package graph");
    }
    checkUnsupportedSource(mod, "compiled Go module");
    checkModuleMetadata(moduleGraphByPath.get(mod.Path) || mod, "compiled Go module");
  }
}

function checkModuleGraphExceptions() {
  for (const mod of moduleGraph) {
    if (mod.Main) continue;
    if (compiledModulePaths.has(mod.Path)) continue;

    if (!reviewedUnusedGooseModules.has(mod.Path)) {
      failures.push(`unreviewed unused Go module graph entry ${mod.Path} ${mod.Version || ""}`.trim());
      continue;
    }
    if (reviewedUnusedGooseModules.get(mod.Path) !== (mod.Version || "")) {
      failures.push(`unused Go module graph exception ${mod.Path} has unreviewed version ${mod.Version || ""}; expected ${reviewedUnusedGooseModules.get(mod.Path)}`);
    }
    if (mod.Path === "gopkg.in/yaml.v3" && mod.Version !== "v3.0.1") {
      failures.push(`gopkg.in/yaml.v3 is only approved as unused goose optional dependency v3.0.1; saw ${mod.Version || "unknown version"}`);
    }
    checkUnsupportedSource(mod, "unused Go module graph exception");
    checkModuleMetadata(mod, "unused Go module graph exception");
  }
}

function checkGoSumPolicy() {
  for (const entry of goSumEntries) {
    if (entry.error) {
      failures.push(entry.error);
      continue;
    }

    if (isReviewedCurrentModuleVersion(entry.path, entry.version)) continue;

    const key = moduleVersionKey(entry.path, entry.version);
    if (entry.goModOnly && reviewedChecksumOnlyGoModSums.has(key)) continue;

    if (reviewedChecksumOnlyGoModSums.has(key)) {
      failures.push(`reviewed checksum-only go.sum exception ${entry.path} ${entry.version} unexpectedly has a module content checksum; only /go.mod is approved`);
      continue;
    }

    const source = currentModuleVersionKeys.has(key) ? "current module graph" : "checksum-only";
    failures.push(`unreviewed ${source} go.sum entry ${entry.path} ${entry.versionToken}`);
  }
}

function isReviewedCurrentModuleVersion(path, version) {
  const graphEntry = moduleGraphByPath.get(path);
  if (!graphEntry || graphEntry.Version !== version) return false;

  return (
    approvedDirectRequires.get(path) === version ||
    approvedCompiledModules.get(path) === version ||
    reviewedUnusedGooseModules.get(path) === version
  );
}

function checkUnsupportedSource(mod, label) {
  if (mod.Replace) {
    failures.push(`${label} ${mod.Path} uses replace directive`);
  }
  if (typeof mod.Version === "string" && /^(?:git|https?|ssh|file):/i.test(mod.Version)) {
    failures.push(`${label} ${mod.Path} has unsupported version source ${mod.Version}`);
  }
}

function checkModuleMetadata(mod, label) {
  if (!mod) return;
  if (typeof mod.Deprecated === "string" && mod.Deprecated.trim() !== "") {
    failures.push(`${label} ${mod.Path} ${mod.Version || ""} is deprecated: ${mod.Deprecated}`.trim());
  }
  if (Array.isArray(mod.Retracted) && mod.Retracted.length > 0) {
    failures.push(`${label} ${mod.Path} ${mod.Version || ""} is retracted: ${mod.Retracted.join("; ")}`.trim());
  }
}

function usedModules(packageEntries) {
  const byPath = new Map();
  for (const pkg of packageEntries) {
    const mod = pkg.Module;
    if (!mod || !mod.Path) continue;
    if (!byPath.has(mod.Path)) byPath.set(mod.Path, mod);
  }
  return [...byPath.values()].sort((a, b) => a.Path.localeCompare(b.Path));
}

function directRequires() {
  return (goMod.Require || []).filter((requirement) => !requirement.Indirect);
}

function reviewedUnusedGraphModules() {
  return moduleGraph.filter((mod) => !mod.Main && !compiledModulePaths.has(mod.Path));
}

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = argv[i + 1];
    if (arg === "--go-mod") {
      parsed.goModPath = value;
      i += 1;
    } else if (arg === "--module-graph") {
      parsed.moduleGraphPath = value;
      i += 1;
    } else if (arg === "--package-graph") {
      parsed.packageGraphPath = value;
      i += 1;
    } else {
      console.error(`unknown argument: ${arg}`);
      process.exit(2);
    }
  }
  return parsed;
}

function parseJSONStream(path) {
  const content = fs.readFileSync(path, "utf8").trim();
  return content ? content.split(/\n(?=\{)/).map((chunk) => JSON.parse(chunk)) : [];
}

function parseGoSum(path) {
  if (!fs.existsSync(path)) return [];

  return fs.readFileSync(path, "utf8")
    .split(/\r?\n/)
    .flatMap((rawLine, index) => {
      const line = rawLine.trim();
      if (line === "") return [];

      const fields = line.split(/\s+/);
      if (fields.length !== 3) {
        return [{
          error: `malformed go.sum entry at ${path}:${index + 1}`
        }];
      }

      const versionToken = fields[1];
      const goModOnly = versionToken.endsWith("/go.mod");
      const version = goModOnly ? versionToken.slice(0, -"/go.mod".length) : versionToken;

      return [{
        path: fields[0],
        versionToken,
        version,
        goModOnly
      }];
    });
}

function versionMap(entries) {
  return new Map(Object.entries(entries).sort(([a], [b]) => a.localeCompare(b)));
}

function moduleVersionSet(entries) {
  return new Set(entries.map(([path, version]) => moduleVersionKey(path, version)));
}

function moduleVersionKey(path, version) {
  return `${path}@${version}`;
}
