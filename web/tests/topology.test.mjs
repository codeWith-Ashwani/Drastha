import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

const read = (name) => readFileSync(new URL("../src/" + name, import.meta.url), "utf8");
// Render the actual TSX through the existing Vite pipeline without listening on
// a port, adding dependencies, or emitting files into the source tree.
const server = await createServer({
  root: fileURLToPath(new URL("..", import.meta.url)),
  server: { middlewareMode: true, hmr: false, watch: null },
});
let component;
try {
  component = await server.ssrLoadModule("/src/HeroTopology.tsx");
} finally {
  await server.close();
}
const render = (active) => renderToStaticMarkup(createElement(component.HeroTopology, { active }));
const css = read("hero.css");

test("maze is idle by default, with no moving packet overlays", () => {
  for (const active of [undefined, false]) {
    const html = render(active);
    assert.match(html, /data-active="false"/);
    assert.doesNotMatch(html, /class="topology-(packets|flow)"/);
    assert.match(html, /aria-hidden="true"/);
  }
});

test("active maze renders packet trails along the existing network and route", () => {
  const html = render(true);
  assert.match(html, /data-active="true"/);
  assert.match(html, /class="topology-packets"/);
  assert.match(html, /class="topology-flow"/);
  assert.equal((html.match(/pathLength="100"/g) ?? []).length, 4);
});

test("ending and restarting activity removes and restores animated overlays", () => {
  for (const active of [true, false, true, false]) {
    assert.equal(render(active).includes('class="topology-packets"'), active);
  }
});

test("all replay entry points drive the maze using existing operation state", () => {
  const app = read("App.tsx");
  assert.match(app, /<HeroTopology active=\{running \|\| uploading \|\| stream\?\.status === "running"\} \/>/);
  assert.match(app, /finally \{ setRunning\(false\); \}/);
  assert.match(app, /finally \{ setUploading\(false\);/);
  assert.match(app, /status: "complete", findings:/);
  assert.match(app, /status: "error"/);
});

test("motion is scoped to active state and disabled for reduced-motion users", () => {
  assert.match(css, /\.hero-topology\[data-active="true"\] \.topology-packets \{ animation: maze-flow 3s linear infinite;/);
  assert.match(css, /\.hero-topology\[data-active="true"\] \.topology-flow \{ animation: maze-flow 8s linear infinite;/);
  assert.doesNotMatch(css, /(?:^|\n)\.topology-pulse\s*\{[^}]*animation:/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)\s*\{\s*\.hero-topology\[data-active="true"\] :is\(\.topology-pulse, \.topology-packets, \.topology-flow\) \{ animation: none;/);
});
