import { PrismaClient } from "@prisma/client";

type PrismaGlobal = typeof globalThis & { __jobenPrisma?: PrismaClient };

const globalForPrisma = globalThis as PrismaGlobal;
let productionClient: PrismaClient | undefined;

export function createPrismaClient(): PrismaClient {
  return new PrismaClient();
}

export function getPrismaClient(): PrismaClient {
  if (process.env.NODE_ENV === "production") {
    productionClient ??= createPrismaClient();
    return productionClient;
  }
  globalForPrisma.__jobenPrisma ??= createPrismaClient();
  return globalForPrisma.__jobenPrisma;
}

export async function checkDatabaseConnection(client = getPrismaClient()): Promise<void> {
  await client.$queryRaw`SELECT 1`;
}

export async function disconnectPrisma(): Promise<void> {
  const client = process.env.NODE_ENV === "production" ? productionClient : globalForPrisma.__jobenPrisma;
  if (client) {
    await client.$disconnect();
    if (process.env.NODE_ENV === "production") productionClient = undefined;
    else delete globalForPrisma.__jobenPrisma;
  }
}