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

function text(value) {
  return String(value ?? "").trim();
}

function lowerText(value) {
  return text(value).toLowerCase();
}

function booleanValue(value) {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    if (lowerText(value) === "true") {
      return true;
    }

    if (lowerText(value) === "false") {
      return false;
    }
  }

  return value;
}

function numberValue(value) {
  if (typeof value === "number") {
    return value;
  }

  if (typeof value === "string" && text(value) !== "") {
    return Number(value);
  }

  return Number.NaN;
}

function hasExactReleasePermissions(permissions = {}) {
  const normalized = Object.fromEntries(
    Object.entries(permissions ?? {}).map(([key, value]) => [
      lowerText(key),
      lowerText(value)
    ])
  );
  const actualKeys = Object.keys(normalized);
  const requiredKeys = Object.keys(REQUIRED_PERMISSIONS);

  return (
    actualKeys.length === requiredKeys.length &&
    requiredKeys.every((key) => normalized[key] === REQUIRED_PERMISSIONS[key])
  );
}

function hasMutableThirdPartyAction(actions = []) {
  return actions.some((action) => {
    if (!action || lowerText(action.owner) === "actions") {
      return false;
    }

    return !FULL_LOWERCASE_SHA.test(text(action.ref));
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
    lowerText(workflow.trigger) === "pull_request_target" ||
    (lowerText(payload.event) === "pull_request" &&
      lowerText(workflow.trigger) !== "pull_request")
  ) {
    violations.push(CODES.UNSAFE_PR_TRIGGER);
  }

  if (
    booleanValue(workflow.testsPass) !== true ||
    booleanValue(workflow.matrixComplete) !== true ||
    booleanValue(workflow.failFast) !== false
  ) {
    violations.push(CODES.TESTS_INCOMPLETE);
  }

  if (hasMutableThirdPartyAction(workflow.actions)) {
    violations.push(CODES.MUTABLE_ACTION);
  }

  if (booleanValue(image.multiStage) !== true) {
    violations.push(CODES.SINGLE_STAGE_IMAGE);
  }

  if (booleanValue(image.runsAsRoot) !== false) {
    violations.push(CODES.ROOT_RUNTIME);
  }

  if (!ALLOWED_SECRET_MODES.has(lowerText(image.secretMode))) {
    violations.push(CODES.SECRET_IN_LAYER);
  }

  if (numberValue(image.criticalVulnerabilities) !== 0) {
    violations.push(CODES.CRITICAL_CVE);
  }

  if (booleanValue(image.digestPinned) !== true) {
    violations.push(CODES.UNPINNED_IMAGE);
  }

  if (lowerText(payload.target) === "production") {
    if (
      lowerText(payload.event) !== "push" ||
      text(payload.ref) !== "refs/heads/main"
    ) {
      violations.push(CODES.INVALID_PRODUCTION_REF);
    }

    if (booleanValue(workflow.environmentApproval) !== true) {
      violations.push(CODES.APPROVAL_REQUIRED);
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations
  };
}

export { CODES };
