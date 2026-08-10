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

  if (typeof value === "number") {
    if (value === 1) {
      return true;
    }

    if (value === 0) {
      return false;
    }
  }

  if (typeof value === "string") {
    if (["true", "yes", "1"].includes(lowerText(value))) {
      return true;
    }

    if (["false", "no", "0"].includes(lowerText(value))) {
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

function read(obj, names) {
  for (const name of names) {
    if (Object.hasOwn(obj ?? {}, name)) {
      return obj[name];
    }
  }

  return undefined;
}

function normalizePermissionKey(key) {
  return lowerText(key).replaceAll("_", "-");
}

function hasExactReleasePermissions(permissions = {}) {
  if (!permissions || typeof permissions !== "object" || Array.isArray(permissions)) {
    return false;
  }

  const normalized = Object.fromEntries(
    Object.entries(permissions ?? {}).map(([key, value]) => [
      normalizePermissionKey(key),
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

function actionParts(action) {
  if (typeof action === "string") {
    const [left, ref = ""] = action.split("@");
    const [owner = "", name = ""] = left.split("/");
    return { owner, name, ref };
  }

  if (typeof action?.uses === "string") {
    return actionParts(action.uses);
  }

  return {
    owner: action?.owner,
    name: action?.name,
    ref: action?.ref
  };
}

function hasMutableThirdPartyAction(actions = []) {
  const list = Array.isArray(actions) ? actions : Object.values(actions ?? {});

  return list.some((action) => {
    const parsed = actionParts(action);

    if (!action || lowerText(parsed.owner) === "actions") {
      return false;
    }

    return !FULL_LOWERCASE_SHA.test(text(parsed.ref));
  });
}

export function evaluateReleaseGate(payload = {}) {
  const workflow = payload.workflow ?? {};
  const image = payload.image ?? {};
  const violations = [];
  const target = lowerText(read(payload, ["target"]));
  const event = lowerText(read(payload, ["event"]));
  const ref = text(read(payload, ["ref"]));
  const trigger = lowerText(read(workflow, ["trigger"]));
  const permissions = read(workflow, ["permissions"]);
  const testsPass = read(workflow, ["testsPass", "tests_pass", "tests_passed"]);
  const matrixComplete = read(workflow, [
    "matrixComplete",
    "matrix_complete",
    "matrixFinished",
    "matrix_finished"
  ]);
  const failFast = read(workflow, ["failFast", "fail_fast"]);
  const environmentApproval = read(workflow, [
    "environmentApproval",
    "environment_approval",
    "approval"
  ]);
  const actions = read(workflow, ["actions", "uses"]);
  const multiStage = read(image, ["multiStage", "multi_stage"]);
  const runsAsRoot = read(image, ["runsAsRoot", "runs_as_root", "root"]);
  const secretMode = read(image, ["secretMode", "secret_mode", "buildSecret", "build_secret"]);
  const criticalVulnerabilities = read(image, [
    "criticalVulnerabilities",
    "critical_vulnerabilities",
    "criticalCVEs",
    "critical_cves"
  ]);
  const digestPinned = read(image, ["digestPinned", "digest_pinned", "pinnedByDigest"]);

  if (!hasExactReleasePermissions(permissions)) {
    violations.push(CODES.EXCESS_PERMISSION);
  }

  if (
    trigger === "pull_request_target" ||
    (event === "pull_request" && trigger !== "pull_request")
  ) {
    violations.push(CODES.UNSAFE_PR_TRIGGER);
  }

  if (
    booleanValue(testsPass) !== true ||
    booleanValue(matrixComplete) !== true ||
    booleanValue(failFast) !== false
  ) {
    violations.push(CODES.TESTS_INCOMPLETE);
  }

  if (hasMutableThirdPartyAction(actions)) {
    violations.push(CODES.MUTABLE_ACTION);
  }

  if (booleanValue(multiStage) !== true) {
    violations.push(CODES.SINGLE_STAGE_IMAGE);
  }

  if (booleanValue(runsAsRoot) !== false) {
    violations.push(CODES.ROOT_RUNTIME);
  }

  if (!ALLOWED_SECRET_MODES.has(lowerText(secretMode))) {
    violations.push(CODES.SECRET_IN_LAYER);
  }

  if (numberValue(criticalVulnerabilities) !== 0) {
    violations.push(CODES.CRITICAL_CVE);
  }

  if (booleanValue(digestPinned) !== true) {
    violations.push(CODES.UNPINNED_IMAGE);
  }

  if (target === "production") {
    if (event !== "push" || ref !== "refs/heads/main") {
      violations.push(CODES.INVALID_PRODUCTION_REF);
    }

    if (booleanValue(environmentApproval) !== true) {
      violations.push(CODES.APPROVAL_REQUIRED);
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations
  };
}

export { CODES };
