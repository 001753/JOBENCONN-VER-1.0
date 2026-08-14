import { AppError } from "./errors.js";
import type { AwsRootMfaObservation } from "./aws.js";

export const ROOT_MFA_CHECK_ID = "AWS-IAM-ROOT-MFA";
export const ROOT_MFA_CHECK_VERSION = "1";
export const ROOT_MFA_EVALUATOR_VERSION = "1";
export const ROOT_MFA_PROVIDER = "aws";
export const ROOT_MFA_SCHEMA_VERSION = "aws-root-mfa.v1";
export const ROOT_MFA_RESOURCE_TYPE = "AWS:IAM:root-account";
export const ROOT_MFA_OPERATION = "IAM.GetAccountSummary";
export const ROOT_MFA_PERMISSION = "iam:GetAccountSummary";
export const ROOT_MFA_COVERAGE = "AWS account root MFA state from IAM account summary";
export const ROOT_MFA_PROVIDER_SOURCE = "AWS IAM API Reference — GetAccountSummary";
export const ROOT_MFA_PROVIDER_SOURCE_REVISION = "https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html";

export const ROOT_MFA_REMEDIATION = {
  title: "Enable multi-factor authentication for the AWS root user",
  reason: "The authoritative account summary reports that root-account MFA is disabled.",
  requiredAction: "Configure MFA for the AWS root user using the AWS account security credentials page.",
  verificationCondition: "A fresh IAM GetAccountSummary response reports AccountMFAEnabled = 1.",
  source: "AWS IAM User Guide — GetAccountSummary / root account MFA",
  version: "2026-08-14",
} as const;

export const ROOT_MFA_SOC2_MAPPING = {
  framework: "SOC 2",
  controlIdentifier: "CC6.1",
  mappingVersion: "1",
  rationale: "Repository-approved mapping for logical access safeguards; this is technical readiness evidence, not a compliance or certification claim.",
  source: "DOC/PRD-JOBEN-ENTERPRISE.md and repository control mapping",
} as const;

export const ROOT_MFA_CONTROL_CONTRACT = {
  checkId: ROOT_MFA_CHECK_ID,
  checkVersion: ROOT_MFA_CHECK_VERSION,
  provider: ROOT_MFA_PROVIDER,
  service: "IAM",
  operation: ROOT_MFA_OPERATION,
  requiredPermissions: [ROOT_MFA_PERMISSION],
  providerSource: ROOT_MFA_PROVIDER_SOURCE,
  providerSourceRevision: ROOT_MFA_PROVIDER_SOURCE_REVISION,
  inputSchema: "AwsRootMfaObservation",
  outputSchema: "RootMfaEvaluation",
  resourceType: ROOT_MFA_RESOURCE_TYPE,
  resourceKeyStrategy: "aws-account:{awsAccountId}:root-mfa",
  observedAt: "provider response completion timestamp",
  coverage: ROOT_MFA_COVERAGE,
  errorTaxonomy: ["PERMISSION_DENIED", "TIMEOUT", "THROTTLED", "TRANSIENT_AWS_FAILURE", "SCHEMA_DRIFT", "EVIDENCE_COMMIT_FAILED", "EVIDENCE_INTEGRITY_FAILED"],
  freshnessExpectation: "fresh provider observation per scan execution",
  evaluatorVersion: ROOT_MFA_EVALUATOR_VERSION,
  provenanceRequirements: ["organizationId", "awsAccountId", "scanRunId", "scanCheckOutcomeId", "evidenceId", "evidenceHash", "observedAt", "correlationId"],
  soc2Mapping: ROOT_MFA_SOC2_MAPPING,
  remediation: ROOT_MFA_REMEDIATION,
  fixtureReference: "test/root-mfa-control.test.ts",
} as const;

export type RootMfaStatus = "PASS" | "FAIL" | "ERROR" | "NOT_APPLICABLE";

export interface RootMfaEvaluation {
  readonly status: RootMfaStatus;
  readonly message: string;
  readonly resourceKey: string;
  readonly coverage: string;
  readonly dataQuality: "AUTHORITATIVE" | "INVALID" | "UNAVAILABLE";
  readonly errorCode?: string;
  readonly remediation?: typeof ROOT_MFA_REMEDIATION;
  readonly soc2Mapping: typeof ROOT_MFA_SOC2_MAPPING;
}

export function rootMfaResourceKey(accountId: string): string {
  if (!/^\d{12}$/.test(accountId)) throw new AppError("VALIDATION_ERROR", "AWS account identity must be a 12-digit account ID.");
  return `aws-account:${accountId}:root-mfa`;
}

export function evaluateRootMfa(observation: AwsRootMfaObservation): RootMfaEvaluation {
  if (!/^\d{12}$/.test(observation.accountId) || !(observation.observedAt instanceof Date) || Number.isNaN(observation.observedAt.getTime()) || typeof observation.mfaEnabled !== "boolean") {
    return {
      status: "ERROR",
      message: "The AWS root MFA observation is malformed and cannot be evaluated.",
      resourceKey: `aws-account:${observation.accountId}:root-mfa`,
      coverage: ROOT_MFA_COVERAGE,
      dataQuality: "INVALID",
      errorCode: "SCHEMA_DRIFT",
      soc2Mapping: ROOT_MFA_SOC2_MAPPING,
    };
  }
  return observation.mfaEnabled
    ? {
        status: "PASS",
        message: "AWS authoritative account summary proves root-account MFA is enabled.",
        resourceKey: rootMfaResourceKey(observation.accountId),
        coverage: ROOT_MFA_COVERAGE,
        dataQuality: "AUTHORITATIVE",
        soc2Mapping: ROOT_MFA_SOC2_MAPPING,
      }
    : {
        status: "FAIL",
        message: "AWS authoritative account summary proves root-account MFA is disabled.",
        resourceKey: rootMfaResourceKey(observation.accountId),
        coverage: ROOT_MFA_COVERAGE,
        dataQuality: "AUTHORITATIVE",
        remediation: ROOT_MFA_REMEDIATION,
        soc2Mapping: ROOT_MFA_SOC2_MAPPING,
      };
}