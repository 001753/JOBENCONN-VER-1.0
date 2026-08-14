import type { Prisma } from "@prisma/client";

export type SecurityEvaluationStatus = "PASS" | "FAIL" | "NOT_APPLICABLE" | "INSUFFICIENT_EVIDENCE";
export type SecuritySeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface SecurityResourceSnapshot {
  readonly id: string;
  readonly accountId: string;
  readonly awsAccountId: string;
  readonly region: string;
  readonly service: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly resourceArn: string | null;
  readonly resourceName: string | null;
  readonly status: string;
  readonly tags: Prisma.JsonValue;
  readonly metadata: Prisma.JsonValue;
}

export interface SecurityEvaluation {
  readonly status: SecurityEvaluationStatus;
  readonly title: string;
  readonly description: string;
  readonly evidence: Record<string, unknown>;
  readonly recommendation: string;
}

export interface SecurityRule {
  readonly ruleId: string;
  readonly version: string;
  readonly enabled?: boolean;
  readonly name: string;
  readonly description: string;
  readonly severity: SecuritySeverity;
  readonly resourceTypes: readonly string[];
  evaluate(resource: SecurityResourceSnapshot): SecurityEvaluation;
}

function metadataRecord(resource: SecurityResourceSnapshot): Record<string, unknown> {
  return resource.metadata && typeof resource.metadata === "object" && !Array.isArray(resource.metadata)
    ? resource.metadata as Record<string, unknown>
    : {};
}

function summaryValue(resource: SecurityResourceSnapshot, key: string): unknown {
  const summary = metadataRecord(resource).summaryMap;
  if (!summary || typeof summary !== "object" || Array.isArray(summary)) return undefined;
  return (summary as Record<string, unknown>)[key];
}

function evidence(status: SecurityEvaluationStatus, field: string, actual: unknown, expected: unknown): Record<string, unknown> {
  return { status, field, actual, expected };
}

const s3EncryptionRule: SecurityRule = {
  ruleId: "AWS-SEC-001",
  version: "1",
  enabled: true,
  name: "S3 bucket default encryption",
  description: "S3 buckets should expose explicit server-side encryption evidence.",
  severity: "HIGH",
  resourceTypes: ["S3:bucket"],
  evaluate(resource) {
    const metadata = metadataRecord(resource);
    const value = metadata.encrypted ?? metadata.encryptionEnabled ?? metadata.serverSideEncryption ?? metadata.encryption;
    if (value === undefined) {
      return {
        status: "INSUFFICIENT_EVIDENCE",
        title: "S3 encryption posture cannot be verified",
        description: "The inventory snapshot does not contain an encryption configuration field for this bucket.",
        evidence: evidence("INSUFFICIENT_EVIDENCE", "metadata.encryption", null, "explicit encryption evidence"),
        recommendation: "Collect the bucket encryption configuration before assessing this control.",
      };
    }
    const normalized = typeof value === "string" ? value.trim().toLowerCase() : value;
    const encrypted = normalized === true || (typeof normalized === "string" && normalized.length > 0 && !["none", "false", "disabled", "unencrypted"].includes(normalized));
    return encrypted
      ? {
          status: "PASS",
          title: "S3 bucket encryption is enabled",
          description: "The inventory contains explicit evidence that server-side encryption is enabled.",
          evidence: evidence("PASS", "metadata.encryption", value, "enabled"),
          recommendation: "Keep default server-side encryption enabled.",
        }
      : {
          status: "FAIL",
          title: "S3 bucket encryption is not enabled",
          description: "The inventory contains explicit evidence that server-side encryption is disabled.",
          evidence: evidence("FAIL", "metadata.encryption", value, "enabled"),
          recommendation: "Enable default server-side encryption using an approved S3 encryption configuration.",
        };
  },
};

const iamMfaRule: SecurityRule = {
  ruleId: "AWS-SEC-002",
  version: "1",
  enabled: true,
  name: "IAM account MFA posture",
  description: "The IAM account summary should report MFA-enabled users.",
  severity: "HIGH",
  resourceTypes: ["IAM:account-summary"],
  evaluate(resource) {
    const value = summaryValue(resource, "AccountMFAEnabled");
    if (value === undefined) {
      return {
        status: "INSUFFICIENT_EVIDENCE",
        title: "IAM account MFA posture cannot be verified",
        description: "The inventory snapshot does not contain AccountMFAEnabled evidence.",
        evidence: evidence("INSUFFICIENT_EVIDENCE", "metadata.summaryMap.AccountMFAEnabled", null, "a numeric count"),
        recommendation: "Collect the IAM account summary with AccountMFAEnabled before assessing this control.",
      };
    }
    const count = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(count)) {
      return {
        status: "INSUFFICIENT_EVIDENCE",
        title: "IAM account MFA posture is malformed",
        description: "AccountMFAEnabled was present but was not a numeric value.",
        evidence: evidence("INSUFFICIENT_EVIDENCE", "metadata.summaryMap.AccountMFAEnabled", value, "a numeric count"),
        recommendation: "Refresh the IAM account summary and preserve the numeric MFA count.",
      };
    }
    return count > 0
      ? {
          status: "PASS",
          title: "IAM account MFA evidence is present",
          description: "The account summary reports at least one MFA-enabled identity.",
          evidence: evidence("PASS", "metadata.summaryMap.AccountMFAEnabled", count, "> 0"),
          recommendation: "Maintain MFA coverage and review identities without MFA separately.",
        }
      : {
          status: "FAIL",
          title: "No IAM MFA-enabled identities reported",
          description: "The account summary reports zero MFA-enabled identities.",
          evidence: evidence("FAIL", "metadata.summaryMap.AccountMFAEnabled", count, "> 0"),
          recommendation: "Enable MFA for IAM identities that can access the account.",
        };
  },
};

const iamRootKeysRule: SecurityRule = {
  ruleId: "AWS-SEC-003",
  version: "1",
  enabled: true,
  name: "IAM account access keys",
  description: "The IAM account summary should report no account-level access keys.",
  severity: "CRITICAL",
  resourceTypes: ["IAM:account-summary"],
  evaluate(resource) {
    const value = summaryValue(resource, "AccountAccessKeysPresent");
    if (value === undefined) {
      return {
        status: "INSUFFICIENT_EVIDENCE",
        title: "IAM account access-key posture cannot be verified",
        description: "The inventory snapshot does not contain AccountAccessKeysPresent evidence.",
        evidence: evidence("INSUFFICIENT_EVIDENCE", "metadata.summaryMap.AccountAccessKeysPresent", null, "0 or 1"),
        recommendation: "Collect the IAM account summary with AccountAccessKeysPresent before assessing this control.",
      };
    }
    const count = typeof value === "number" ? value : Number(value);
    if (!Number.isFinite(count)) {
      return {
        status: "INSUFFICIENT_EVIDENCE",
        title: "IAM account access-key posture is malformed",
        description: "AccountAccessKeysPresent was present but was not numeric.",
        evidence: evidence("INSUFFICIENT_EVIDENCE", "metadata.summaryMap.AccountAccessKeysPresent", value, "0 or 1"),
        recommendation: "Refresh the IAM account summary and preserve the numeric access-key value.",
      };
    }
    return count === 0
      ? {
          status: "PASS",
          title: "No IAM account access keys reported",
          description: "The account summary reports no account-level access keys.",
          evidence: evidence("PASS", "metadata.summaryMap.AccountAccessKeysPresent", count, 0),
          recommendation: "Continue using short-lived or role-based access where possible.",
        }
      : {
          status: "FAIL",
          title: "IAM account-level access keys are present",
          description: "The account summary reports account-level access keys.",
          evidence: evidence("FAIL", "metadata.summaryMap.AccountAccessKeysPresent", count, 0),
          recommendation: "Remove account-level access keys and use short-lived role-based credentials.",
        };
  },
};

const ec2PublicExposureRule: SecurityRule = {
  ruleId: "AWS-SEC-004",
  version: "1",
  enabled: true,
  name: "EC2 public exposure",
  description: "EC2 instances should not expose a public address unless explicitly assessed.",
  severity: "HIGH",
  resourceTypes: ["EC2:instance"],
  evaluate(resource) {
    const metadata = metadataRecord(resource);
    const field = ["publicAccess", "publicIpAddress", "associatePublicIpAddress"].find((key) => metadata[key] !== undefined);
    if (!field) {
      return {
        status: "INSUFFICIENT_EVIDENCE",
        title: "EC2 public exposure cannot be verified",
        description: "The inventory snapshot does not contain public-address evidence for this instance.",
        evidence: evidence("INSUFFICIENT_EVIDENCE", "metadata.publicIpAddress", null, "explicit public exposure evidence"),
        recommendation: "Collect public IP and network exposure metadata before assessing this control.",
      };
    }
    const value = metadata[field];
    const exposed = value === true || (typeof value === "string" && value.trim().length > 0) || (Array.isArray(value) && value.length > 0);
    return exposed
      ? {
          status: "FAIL",
          title: "EC2 instance has public exposure evidence",
          description: "The inventory contains an explicit public-address or public-access value.",
          evidence: evidence("FAIL", `metadata.${field}`, value, false),
          recommendation: "Remove unnecessary public exposure and restrict access through private networking and controlled ingress.",
        }
      : {
          status: "PASS",
          title: "EC2 instance has no public exposure evidence",
          description: "The inventory contains explicit evidence that the instance is not publicly exposed.",
          evidence: evidence("PASS", `metadata.${field}`, value, false),
          recommendation: "Keep the instance on private networking unless public exposure is required and reviewed.",
        };
  },
};

export const SECURITY_RULES: readonly SecurityRule[] = [
  s3EncryptionRule,
  iamMfaRule,
  iamRootKeysRule,
  ec2PublicExposureRule,
];

export function applicableSecurityRules(resource: SecurityResourceSnapshot, rules: readonly SecurityRule[] = SECURITY_RULES): readonly SecurityRule[] {
  const type = `${resource.service}:${resource.resourceType}`;
  return rules.filter((rule) => rule.enabled !== false && rule.resourceTypes.includes(type));
}