const CODES = {
  EXCESS_PERMISSION: "EXCESS_PERMISSION",
  UNSAFE_PR_TRIGGER: "UNSAFE_PR_TRIGGER",
  TESTS_INCOMPLETE: "TESTS_INCOMPLETE",
  MUTABLE_ACTION: "MUTABLE_ACTION",
  SINGLE_STAGE_IMAGE: "SINGLE_STAGE_IMAGE",
  ROOT_RUNTIME: "ROOT_RUNTIME",
  SECRET_IN_LAYER: "SECRET_IN_LAYER",
  CRITICAL_CVE: "CRITICAL_CVE",
  UNPINNED_IMAGE: "UNPINNED_IMAGE",
  INVALID_PRODUCTION_REF: "INVALID_PRODUCTION_REF",
  APPROVAL_REQUIRED: "APPROVAL_REQUIRED"
};

const REQUIRED_PERMISSIONS = {
  contents: "read",
  packages: "write",
  "id-token": "none"
};

const FULL_LOWERCASE_SHA = /^[0-9a-f]{40}$/;
const ALLOWED_SECRET_MODES = new Set(["none", "buildkit"]);

function hasExactReleasePermissions(permissions = {}) {
  const actualKeys = Object.keys(permissions);
  const requiredKeys = Object.keys(REQUIRED_PERMISSIONS);

  return (
    actualKeys.length === requiredKeys.length &&
    requiredKeys.every((key) => permissions[key] === REQUIRED_PERMISSIONS[key])
  );
}

function hasMutableThirdPartyAction(actions = []) {
  return actions.some((action) => {
    if (!action || action.owner === "actions") {
      return false;
    }

    return !FULL_LOWERCASE_SHA.test(String(action.ref ?? ""));
  });
}

export function evaluateReleaseGate(payload = {}) {
  const workflow = payload.workflow ?? {};
  const image = payload.image ?? {};
  const violations = [];

  if (!hasExactReleasePermissions(workflow.permissions)) {
    violations.push(CODES.EXCESS_PERMISSION);
  }

  if (
    workflow.trigger === "pull_request_target" ||
    (payload.event === "pull_request" && workflow.trigger !== "pull_request")
  ) {
    violations.push(CODES.UNSAFE_PR_TRIGGER);
  }

  if (
    workflow.testsPass !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push(CODES.TESTS_INCOMPLETE);
  }

  if (hasMutableThirdPartyAction(workflow.actions)) {
    violations.push(CODES.MUTABLE_ACTION);
  }

  if (image.multiStage !== true) {
    violations.push(CODES.SINGLE_STAGE_IMAGE);
  }

  if (image.runsAsRoot !== false) {
    violations.push(CODES.ROOT_RUNTIME);
  }

  if (!ALLOWED_SECRET_MODES.has(image.secretMode)) {
    violations.push(CODES.SECRET_IN_LAYER);
  }

  if (image.criticalVulnerabilities !== 0) {
    violations.push(CODES.CRITICAL_CVE);
  }

  if (image.digestPinned !== true) {
    violations.push(CODES.UNPINNED_IMAGE);
  }

  if (payload.target === "production") {
    if (payload.event !== "push" || payload.ref !== "refs/heads/main") {
      violations.push(CODES.INVALID_PRODUCTION_REF);
    }

    if (workflow.environmentApproval !== true) {
      violations.push(CODES.APPROVAL_REQUIRED);
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations
  };
}

export { CODES };
