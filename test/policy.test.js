import assert from "node:assert/strict";
import test from "node:test";
import { evaluateReleaseGate } from "../src/policy.js";

const safePreviewPayload = {
  target: "preview",
  event: "pull_request",
  ref: "refs/heads/feature",
  workflow: {
    trigger: "pull_request",
    permissions: {
      contents: "read",
      packages: "write",
      "id-token": "none"
    },
    testsPass: true,
    matrixComplete: true,
    failFast: false,
    actions: [
      { owner: "actions", name: "checkout", ref: "v4" },
      {
        owner: "docker",
        name: "login-action",
        ref: "0123456789abcdef0123456789abcdef01234567"
      }
    ]
  },
  image: {
    multiStage: true,
    runsAsRoot: false,
    secretMode: "buildkit",
    criticalVulnerabilities: 0,
    digestPinned: true
  }
};

test("promotes a safe preview pull request", () => {
  assert.deepEqual(evaluateReleaseGate(safePreviewPayload), {
    decision: "promote",
    violations: []
  });
});

test("promotes a safe production push to main with approval", () => {
  const result = evaluateReleaseGate({
    ...safePreviewPayload,
    target: "production",
    event: "push",
    ref: "refs/heads/main",
    workflow: {
      ...safePreviewPayload.workflow,
      trigger: "push",
      environmentApproval: true
    }
  });

  assert.deepEqual(result, {
    decision: "promote",
    violations: []
  });
});

test("blocks combined workflow, action, image, and production failures", () => {
  const result = evaluateReleaseGate({
    target: "production",
    event: "pull_request",
    ref: "refs/heads/feature",
    workflow: {
      trigger: "pull_request_target",
      permissions: {
        contents: "write",
        packages: "write",
        "id-token": "write",
        actions: "read"
      },
      testsPass: false,
      matrixComplete: false,
      failFast: true,
      environmentApproval: false,
      actions: [
        { owner: "actions", name: "checkout", ref: "v4" },
        { owner: "third-party", name: "deploy", ref: "v1" },
        {
          owner: "third-party",
          name: "upper-sha",
          ref: "0123456789ABCDEF0123456789ABCDEF01234567"
        }
      ]
    },
    image: {
      multiStage: false,
      runsAsRoot: true,
      secretMode: "copy",
      criticalVulnerabilities: 1,
      digestPinned: false
    }
  });

  assert.equal(result.decision, "block");
  assert.deepEqual(new Set(result.violations), new Set([
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED"
  ]));
});

test("allows no build secret and rejects missing digest pin", () => {
  const result = evaluateReleaseGate({
    ...safePreviewPayload,
    image: {
      ...safePreviewPayload.image,
      secretMode: "none",
      digestPinned: false
    }
  });

  assert.deepEqual(result, {
    decision: "block",
    violations: ["UNPINNED_IMAGE"]
  });
});

test("blocks pull_request_target even when event fields are inconsistent", () => {
  const result = evaluateReleaseGate({
    ...safePreviewPayload,
    event: "push",
    workflow: {
      ...safePreviewPayload.workflow,
      trigger: "pull_request_target"
    }
  });

  assert.equal(result.decision, "block");
  assert.ok(result.violations.includes("UNSAFE_PR_TRIGGER"));
});

test("normalizes string values used by external probes", () => {
  const result = evaluateReleaseGate({
    target: "production",
    event: "push",
    ref: "refs/heads/main",
    workflow: {
      trigger: "push",
      permissions: {
        contents: "read",
        packages: "write",
        "id-token": "none"
      },
      testsPass: "true",
      matrixComplete: "true",
      failFast: "false",
      environmentApproval: "true",
      actions: [
        { owner: "Actions", name: "checkout", ref: "v4" },
        {
          owner: "docker",
          name: "metadata-action",
          ref: "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
        }
      ]
    },
    image: {
      multiStage: "true",
      runsAsRoot: "false",
      secretMode: "BuildKit",
      criticalVulnerabilities: "0",
      digestPinned: "true"
    }
  });

  assert.deepEqual(result, {
    decision: "promote",
    violations: []
  });
});
