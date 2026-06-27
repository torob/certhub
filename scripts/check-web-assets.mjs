#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const roots = process.argv.slice(2);
if (roots.length === 0) {
  console.error("usage: check-web-assets.mjs <path>...");
  process.exit(2);
}

const failures = [];
const scanned = [];
const textExtensions = new Set([
  ".css",
  ".html",
  ".js",
  ".json",
  ".jsx",
  ".mjs",
  ".svg",
  ".ts",
  ".tsx",
  ".txt",
  ".xml"
]);

function hasNetworkLoadingContext(content, index) {
  const prefix = content.slice(Math.max(0, index - 120), index);
  return /(?:fetch|importScripts|Worker|SharedWorker|EventSource|WebSocket|import)\s*\(\s*["'`]?$/.test(prefix) ||
    /<(?:script|link|img|source|iframe|audio|video|embed|object|use|image)\b[^>]*(?:src|href|srcset|poster|data)=["'`]?$/i.test(prefix) ||
    /(?:^|[\s{;])(?:src|href|srcset|poster|data)\s*:\s*["'`]?$/i.test(prefix) ||
    /@import\s+(?:url\s*\(\s*)?["'`]?$/.test(prefix) ||
    /url\s*\(\s*["'`]?$/.test(prefix);
}

function isAllowedDiagnosticUrl(url, target, content, index) {
  if (hasNetworkLoadingContext(content, index)) return "";
  if (
    (url.startsWith("http://www.w3.org/") || url.startsWith("https://www.w3.org/")) &&
    /\.(?:svg|html|xml|js|mjs)$/i.test(target)
  ) {
    return "W3C namespace identifier, not a fetched browser dependency";
  }
  if (url.startsWith("https://react.dev/errors/") && /\.(?:js|mjs)$/i.test(target)) {
    return "React production diagnostic error-code reference";
  }
  if (url.startsWith("https://reactrouter.com/") && /\.(?:js|mjs)$/i.test(target)) {
    return "React Router production diagnostic documentation reference";
  }
  if (url === "http://localhost" && /\.(?:js|mjs)$/i.test(target)) {
    return "React Router URL-constructor fallback base, not a fetched browser dependency";
  }
  return "";
}

function isInsideHtmlComment(content, index) {
  return content.lastIndexOf("<!--", index) > content.lastIndexOf("-->", index);
}

function isInsideHtmlScript(content, index) {
  const before = content.slice(0, index).toLowerCase();
  return before.lastIndexOf("<script") > before.lastIndexOf("</script");
}

function isInsideBlockComment(content, index) {
  return content.lastIndexOf("/*", index) > content.lastIndexOf("*/", index);
}

function hasLineCommentBefore(content, index) {
  const lineStart = content.lastIndexOf("\n", index - 1) + 1;
  let quote = "";
  let escaped = false;
  for (let i = lineStart; i < index; i += 1) {
    const char = content[i];
    const next = content[i + 1];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (quote) {
      if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = "";
      }
      continue;
    }
    if (char === "\"" || char === "'" || char === "`") {
      quote = char;
      continue;
    }
    if (char === "/" && next === "/" && content[i - 1] !== ":") {
      return true;
    }
  }
  return false;
}

function isOrdinaryComment(content, index, target) {
  const ext = path.extname(target).toLowerCase();
  if ([".html", ".svg", ".xml"].includes(ext) && isInsideHtmlComment(content, index) && !isInsideHtmlScript(content, index)) {
    return true;
  }
  if (isInsideBlockComment(content, index)) return true;
  if ([".js", ".jsx", ".mjs", ".ts", ".tsx", ".css"].includes(ext)) {
    return hasLineCommentBefore(content, index);
  }
  return false;
}

function walk(target) {
  if (!fs.existsSync(target)) return;
  const stat = fs.lstatSync(target);
  if (stat.isSymbolicLink()) {
    failures.push(`${target} is a symlink`);
    return;
  }
  if (stat.isDirectory()) {
    for (const child of fs.readdirSync(target)) walk(path.join(target, child));
    return;
  }
  if (!stat.isFile()) return;
  if (!textExtensions.has(path.extname(target))) return;
  scanned.push(target);
  const base = path.basename(target);
  if (base.endsWith(".map")) failures.push(`${target} is a source map`);
  const content = fs.readFileSync(target, "utf8");
  const isDist = target.split(path.sep).includes("dist");
  for (const match of content.matchAll(/https?:\/\/[^"'`)\\\s]+/gi)) {
    const url = match[0];
    const allowedReason = isAllowedDiagnosticUrl(url, target, content, match.index || 0);
    if (allowedReason) {
      continue;
    }
    failures.push(`${target} contains a disallowed external URL: ${url}`);
  }
  for (const match of content.matchAll(/(^|[^:])\/\/[^"'`)\\\s<]+/g)) {
    const offset = match[1].length;
    const index = (match.index || 0) + offset;
    const url = match[0].slice(offset);
    if (isOrdinaryComment(content, index, target) && !hasNetworkLoadingContext(content, index)) {
      continue;
    }
    failures.push(`${target} contains a disallowed protocol-relative URL: ${url}`);
  }
  if (/sourceMappingURL=/i.test(content)) failures.push(`${target} contains a sourceMappingURL reference`);
  if (!isDist && /\bdangerouslySetInnerHTML\b/.test(content)) failures.push(`${target} references dangerouslySetInnerHTML`);
  if (/\beval\s*\(/.test(content) || /\bnew\s+Function\s*\(/.test(content)) {
    failures.push(`${target} references eval-like code execution`);
  }
}

for (const root of roots) walk(root);

if (failures.length > 0) {
  console.error("Web asset policy failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Web asset policy passed: ${scanned.length} file(s) scanned.`);
