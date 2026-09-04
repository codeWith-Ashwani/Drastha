import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (name) => readFileSync(new URL("../src/" + name, import.meta.url), "utf8");
const base = read("styles.css");
const hero = read("hero.css");
const root = base.match(/:root\s*\{([^}]+)\}/)[1];
const tokens = new Map([...root.matchAll(/(--[\w-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2]]));

test("header uses the selected blue glowing logo with accessible text and preserved proportions", () => {
  const app = read("App.tsx");
  assert.match(app, /className="brand-logo" src="\/images\/drastha-logo-blue\.png" alt="Drastha"/);
  assert.match(base, /\.brand-logo\s*\{[^}]*height: auto;[^}]*object-fit: contain;/);
  const png = readFileSync(new URL("../public/images/drastha-logo-blue.png", import.meta.url));
  assert.equal(png.subarray(0, 8).toString("hex"), "89504e470d0a1a0a");
  assert.equal(png.readUInt32BE(16), 1536);
  assert.equal(png.readUInt32BE(20), 1024);
});

test("hero and analyst surfaces share defined design tokens", () => {
  for (const source of [base, hero]) {
    for (const match of source.matchAll(/var\((--[\w-]+)/g)) {
      assert.ok(tokens.has(match[1]), "Undefined token: " + match[1]);
    }
  }
  assert.doesNotMatch(base.replace(/:root\s*\{[^}]+\}/, "") + hero, /#[0-9a-f]{3,8}\b/i);
  assert.doesNotMatch(base + hero, /--blue|--hero-accent/);
});

test("regular copy, controls and metadata keep readable minimum sizes", () => {
  assert.equal(tokens.get("--font-body"), "1rem");
  assert.equal(tokens.get("--font-label"), ".875rem");
  assert.equal(tokens.get("--font-meta"), ".75rem");
  for (const match of (base + hero).matchAll(/font-size:\s*([\d.]+)(px|rem)\b/g)) {
    assert.ok(Number(match[1]) * (match[2] === "rem" ? 16 : 1) >= 12);
  }
  assert.match(base, /\.app-shell :is\(button, a, input, select, textarea\):focus-visible/);
  assert.match(base, /prefers-reduced-motion: reduce/);
});

test("text palette meets normal-text contrast on shared surfaces", () => {
  const luminance = (hex) => {
    const channels = hex.slice(1).match(/../g).map((v) => {
      const c = parseInt(v, 16) / 255;
      return c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4;
    });
    return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722;
  };
  for (const foreground of ["--text", "--text-secondary", "--muted", "--accent-bright"]) {
    for (const background of ["--bg", "--surface", "--surface-2", "--surface-inset", "--surface-hover"]) {
      const ratio = (luminance(tokens.get(foreground)) + .05) / (luminance(tokens.get(background)) + .05);
      assert.ok(ratio >= 4.5, foreground + " on " + background + ": " + ratio);
    }
  }
});

test("severity and telemetry status retain distinct semantic colours", () => {
  for (const [name, token] of [["critical", "red"], ["high", "amber"], ["low", "green"]]) {
    assert.match(base, new RegExp("\\.severity-" + name + " \\{[^}]+var\\(--" + token + "-text\\)"));
  }
  assert.notEqual(tokens.get("--red"), tokens.get("--accent"));
  assert.notEqual(tokens.get("--green"), tokens.get("--accent"));
  assert.match(base, /\.live-complete \{ border-left-color: var\(--green\)/);
  assert.match(base, /\.live-error \{ border-left-color: var\(--red\)/);
});

test("uploaded replay separates all four analysis outcome categories", () => {
  const app = read("App.tsx");
  for (const heading of ["Detected threat", "Approved context", "Insufficient evidence", "Invalid / rejected input"]) {
    assert.match(app, new RegExp(heading.replace("/", "\\/")));
  }
  assert.match(app, /Not classified as benign or malicious/);
  assert.match(app, /suppressed_by_detector/);
  assert.match(base, /\.analysis-status-grid/);
});

test("dashboard presents one bounded replay-wide risk without calling it probability", () => {
  const app = read("App.tsx");
  const component = read("OverallRisk.tsx");
  assert.match(app, /uploadResult\.overall_risk && <OverallRisk value=\{uploadResult\.overall_risk\}/);
  assert.match(component, /Overall replay risk/);
  assert.match(component, /overall investigation priority/);
  assert.match(base, /\.overall-risk/);
});
