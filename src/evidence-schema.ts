import { AppError } from "./errors.js";

export interface ProviderSchema {
  readonly provider: string;
  readonly schemaVersion: string;
  validate(payload: unknown): void;
}

function objectPayload(payload: unknown, label: string): Record<string, unknown> {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new AppError("SCHEMA_ERROR", `schema_error: ${label} must be an object`);
  }
  return payload as Record<string, unknown>;
}

function stringField(payload: Record<string, unknown>, field: string): void {
  if (payload[field] !== undefined && typeof payload[field] !== "string") {
    throw new AppError("SCHEMA_ERROR", `schema_error: ${field} must be a string`);
  }
}

const awsProviderSchema: ProviderSchema = {
  provider: "aws",
  schemaVersion: "aws.v1",
  validate(payload) {
    const record = objectPayload(payload, "aws.v1 payload");
    ["accountId", "region", "service", "resourceId", "requestId"].forEach((field) => stringField(record, field));
    if (!["accountId", "region", "service", "resourceId", "requestId", "resources"].some((field) => record[field] !== undefined)) {
      throw new AppError("SCHEMA_ERROR", "schema_error: aws.v1 requires provider identity fields");
    }
    if (record.resources !== undefined && (!Array.isArray(record.resources) || record.resources.some((item) => typeof item !== "object" || item === null))) {
      throw new AppError("SCHEMA_ERROR", "schema_error: aws.v1 resources must be an array of objects");
    }
  },
};

const awsDiscoverySchema: ProviderSchema = {
  provider: "aws-discovery",
  schemaVersion: "aws-discovery.v1",
  validate(payload) {
    const record = objectPayload(payload, "aws-discovery.v1 payload");
    if (typeof record.accountId !== "string" || !Array.isArray(record.resources)) {
      throw new AppError("SCHEMA_ERROR", "schema_error: aws-discovery.v1 requires accountId and resources");
    }
  },
};

const awsSecuritySchema: ProviderSchema = {
  provider: "aws-security",
  schemaVersion: "aws-security.v1",
  validate(payload) {
    const record = objectPayload(payload, "aws-security.v1 payload");
    if (typeof record.accountId !== "string" || !Array.isArray(record.resources)) {
      throw new AppError("SCHEMA_ERROR", "schema_error: aws-security.v1 requires accountId and resources");
    }
  },
};

const awsRootMfaSchema: ProviderSchema = {
  provider: "aws",
  schemaVersion: "aws-root-mfa.v1",
  validate(payload) {
    const record = objectPayload(payload, "aws-root-mfa.v1 payload");
    if (typeof record.accountId !== "string" || !/^\d{12}$/.test(record.accountId)) {
      throw new AppError("SCHEMA_ERROR", "schema_error: aws-root-mfa.v1 requires a valid accountId");
    }
    if (record.service !== "IAM" || record.operation !== "IAM.GetAccountSummary") {
      throw new AppError("SCHEMA_ERROR", "schema_error: aws-root-mfa.v1 requires the IAM GetAccountSummary operation");
    }
    if (typeof record.mfaEnabled !== "boolean") {
      throw new AppError("SCHEMA_ERROR", "schema_error: aws-root-mfa.v1 requires boolean mfaEnabled");
    }
    if (record.requestId !== undefined && typeof record.requestId !== "string") {
      throw new AppError("SCHEMA_ERROR", "schema_error: requestId must be a string");
    }
  },
};

const testSchema: ProviderSchema = {
  provider: "test",
  schemaVersion: "test.v1",
  validate(payload) {
    const record = objectPayload(payload, "test.v1 payload");
    if (typeof record.fixture !== "string") throw new AppError("SCHEMA_ERROR", "schema_error: test.v1 requires fixture");
  },
};

const schemas = new Map<string, ProviderSchema>([
  [`${awsProviderSchema.provider}:${awsProviderSchema.schemaVersion}`, awsProviderSchema],
  [`${awsDiscoverySchema.provider}:${awsDiscoverySchema.schemaVersion}`, awsDiscoverySchema],
  [`${awsSecuritySchema.provider}:${awsSecuritySchema.schemaVersion}`, awsSecuritySchema],
  [`${awsRootMfaSchema.provider}:${awsRootMfaSchema.schemaVersion}`, awsRootMfaSchema],
  [`${testSchema.provider}:${testSchema.schemaVersion}`, testSchema],
]);

export function validateProviderEvidence(provider: string, schemaVersion: string, payload: unknown): void {
  const schema = schemas.get(`${provider}:${schemaVersion}`);
  if (!schema) throw new AppError("SCHEMA_ERROR", "schema_error: unsupported provider schema");
  schema.validate(payload);
}
