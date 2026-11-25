import assert from "node:assert/strict";
import test from "node:test";
import { versionRevokeBody, versionRevokeStep } from "../src/version-revoke.ts";

const version = { id: "version-1", version: 3, status: "valid" };

test("the Revoke row action opens a confirmation and sends no request", () => {
  assert.deepEqual(versionRevokeStep(undefined, { type: "request", version }), { confirming: version });
});

test("confirming sends one revoke request for the selected version and keeps the dialog open while it runs", () => {
  assert.deepEqual(versionRevokeStep(version, { type: "confirm" }), { confirming: version, send: version });
});

test("closing the confirmation sends no request", () => {
  assert.deepEqual(versionRevokeStep(version, { type: "close" }), {});
});

test("confirm without an open confirmation sends no request", () => {
  assert.deepEqual(versionRevokeStep(undefined, { type: "confirm" }), {});
});

test("cancel, then revoke and confirm, sends exactly one request", () => {
  const sent: unknown[] = [];
  let confirming: typeof version | undefined;
  for (const event of [{ type: "request", version }, { type: "close" }, { type: "request", version }, { type: "confirm" }] as const) {
    const step = versionRevokeStep(confirming, event);
    confirming = step.confirming;
    if (step.send) sent.push(step.send);
  }
  assert.deepEqual(sent, [version]);
});

test("the revoke request body is unchanged", () => {
  assert.equal(JSON.stringify(versionRevokeBody), JSON.stringify({ reason: "cessation_of_operation" }));
});
