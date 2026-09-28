import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createServer } from "vite";

const server = await createServer({
  root: fileURLToPath(new URL("..", import.meta.url)),
  server: { middlewareMode: true, hmr: false, watch: null },
});
let apiErrorMessage;
try { ({ apiErrorMessage } = await server.ssrLoadModule("/src/apiError.ts")); }
finally { await server.close(); }

test("PCAP request validation shows the rejected field, not an object string", () => {
  const error = { detail: [{
    type: "string_too_long", loc: ["body", "filename"],
    msg: "String should have at most 120 characters", input: "private file name",
  }] };
  assert.equal(apiErrorMessage(error, 422), "filename: String should have at most 120 characters");
  assert.doesNotMatch(apiErrorMessage(error, 422), /object Object|private file name/);
});

test("multiple validation issues are readable without exposing submitted capture data", () => {
  const error = { detail: [
    { loc: ["body", "content_base64"], msg: "String should have at most 6666668 characters", input: "capture bytes" },
    { loc: ["body", "filename"], msg: "Field required" },
  ] };
  assert.equal(apiErrorMessage(error, 422),
    "content_base64: String should have at most 6666668 characters; filename: Field required");
  assert.doesNotMatch(apiErrorMessage(error, 422), /capture bytes/);
});

test("plain API errors and malformed responses remain actionable", () => {
  assert.equal(apiErrorMessage({ detail: "Upload a classic .pcap file." }, 422), "Upload a classic .pcap file.");
  assert.equal(apiErrorMessage({ detail: { unexpected: true } }, 422), "Request failed (HTTP 422).");
  assert.equal(apiErrorMessage(null, 500), "Request failed (HTTP 500).");
});
