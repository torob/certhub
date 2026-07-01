import { createElement } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app";
import "./styles.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing root element");
}
const rootElement = root;

async function boot() {
  const runtimeConfigPath = "/certhub-runtime-config.js";
  await import(/* @vite-ignore */ runtimeConfigPath).catch(() => undefined);
  createRoot(rootElement).render(createElement(App));
}

void boot();
