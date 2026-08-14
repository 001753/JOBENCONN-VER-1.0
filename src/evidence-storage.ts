import { randomUUID } from "node:crypto";
import { timingSafeEqual } from "node:crypto";
import { AppError } from "./errors.js";
import { sha256Hex } from "./evidence-canonical.js";

export interface StorageCapabilities {
  readonly encryption: "SSE-S3";
  readonly versioning: true;
  readonly objectLockCompatible: true;
  readonly liveVerified: false;
}

export interface StoredObject {
  readonly key: string;
  readonly versionId: string;
  readonly contentHash: string;
  readonly retentionUntil: Date;
  readonly encryption: "SSE-S3";
  readonly createdAt: Date;
}

export interface EvidenceObjectStorage {
  readonly capabilities: StorageCapabilities;
  put(input: { key: string; bytes: Uint8Array; contentHash: string; retentionUntil: Date }): Promise<StoredObject>;
  get(key: string, versionId?: string): Promise<Uint8Array | null>;
  head(key: string, versionId?: string): Promise<StoredObject | null>;
  delete(key: string, versionId: string, now?: Date): Promise<void>;
}

interface StoredVersion extends StoredObject {
  bytes: Uint8Array;
}

/**
 * Deterministic WORM-compatible adapter for tests and local integrity drills.
 * It has versioned immutable writes, but is not a claim of live AWS Object Lock.
 */
export class InMemoryEvidenceObjectStorage implements EvidenceObjectStorage {
  readonly capabilities: StorageCapabilities = {
    encryption: "SSE-S3",
    versioning: true,
    objectLockCompatible: true,
    liveVerified: false,
  };
  private readonly objects = new Map<string, Map<string, StoredVersion>>();

  async put(input: { key: string; bytes: Uint8Array; contentHash: string; retentionUntil: Date }): Promise<StoredObject> {
    if (sha256Hex(input.bytes) !== input.contentHash) {
      throw new AppError("INTEGRITY_ERROR", "Object content hash does not match supplied bytes.");
    }
    const versions = this.objects.get(input.key) ?? new Map<string, StoredVersion>();
    for (const existing of versions.values()) {
      const sameLength = existing.bytes.byteLength === input.bytes.byteLength;
      const sameBytes = sameLength && timingSafeEqual(Buffer.from(existing.bytes), Buffer.from(input.bytes));
      if (sameBytes) return this.publicMetadata(existing);
    }
    if (versions.size > 0) throw new AppError("CONFLICT", "Content-addressed object already exists with different bytes.");
    const versionId = randomUUID();
    const stored: StoredVersion = {
      key: input.key,
      versionId,
      contentHash: input.contentHash,
      retentionUntil: new Date(input.retentionUntil),
      encryption: "SSE-S3",
      createdAt: new Date(),
      bytes: new Uint8Array(input.bytes),
    };
    versions.set(versionId, stored);
    this.objects.set(input.key, versions);
    return this.publicMetadata(stored);
  }

  async get(key: string, versionId?: string): Promise<Uint8Array | null> {
    const stored = this.resolve(key, versionId);
    return stored ? new Uint8Array(stored.bytes) : null;
  }

  async head(key: string, versionId?: string): Promise<StoredObject | null> {
    const stored = this.resolve(key, versionId);
    return stored ? this.publicMetadata(stored) : null;
  }

  async delete(key: string, versionId: string, now = new Date()): Promise<void> {
    const versions = this.objects.get(key);
    const stored = versions?.get(versionId);
    if (!stored) return;
    if (stored.retentionUntil > now) throw new AppError("RETENTION_CONFLICT", "Object retention has not expired.");
    versions?.delete(versionId);
    if (versions?.size === 0) this.objects.delete(key);
  }

  /** Test-only corruption hook used by the integrity drill. */
  corrupt(key: string, versionId: string, bytes: Uint8Array): void {
    const stored = this.objects.get(key)?.get(versionId);
    if (!stored) throw new AppError("NOT_FOUND", "Object not found.");
    stored.bytes = new Uint8Array(bytes);
  }

  private resolve(key: string, versionId?: string): StoredVersion | null {
    const versions = this.objects.get(key);
    if (!versions) return null;
    if (versionId) return versions.get(versionId) ?? null;
    return [...versions.values()].at(-1) ?? null;
  }

  private publicMetadata(stored: StoredVersion): StoredObject {
    const { bytes: _bytes, ...metadata } = stored;
    return metadata;
  }
}

export const storageCapabilities: StorageCapabilities = {
  encryption: "SSE-S3",
  versioning: true,
  objectLockCompatible: true,
  liveVerified: false,
};
