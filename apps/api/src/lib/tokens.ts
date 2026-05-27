/**
 * tokens.ts — JWT signing, verification, and Redis-backed revocation list.
 * Access token TTL: 15 min | Refresh token TTL: 30 days
 */
import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import { redis } from "./redis";
import { config } from "./config";

export const ACCESS_TOKEN_TTL = "15m";
export const REFRESH_TOKEN_TTL = "30d";
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;

export interface AccessPayload { sub: string; email: string; jti: string; iat: number; exp: number; }
export interface RefreshPayload { sub: string; email: string; type: "refresh"; jti: string; iat: number; exp: number; }

function accessSecret() { return config.JWT_SECRET; }
function refreshSecret() { return config.JWT_REFRESH_SECRET ?? config.JWT_SECRET; }

export function signAccessToken(user: { id: string; email: string }): string {
  return jwt.sign({ sub: user.id, email: user.email, jti: randomUUID() }, accessSecret(), { expiresIn: ACCESS_TOKEN_TTL });
}

export function signRefreshToken(user: { id: string; email: string }): string {
  return jwt.sign({ sub: user.id, email: user.email, type: "refresh", jti: randomUUID() }, refreshSecret(), { expiresIn: REFRESH_TOKEN_TTL });
}

export function verifyAccessToken(token: string): AccessPayload {
  return jwt.verify(token, accessSecret()) as AccessPayload;
}

export function verifyRefreshToken(token: string): RefreshPayload {
  const p = jwt.verify(token, refreshSecret()) as RefreshPayload;
  if (p.type !== "refresh") throw new Error("Not a refresh token");
  return p;
}

const jtiKey = (jti: string) => `jti:${jti}`;
const userRefreshSetKey = (uid: string) => `user_refresh_jtis:${uid}`;

/** Returns true if jti was already used (reuse detected). */
export async function markJtiUsed(jti: string): Promise<boolean> {
  const result = await redis.set(jtiKey(jti), "used", "EX", REFRESH_TTL_SECONDS, "NX");
  return result === null;
}

export async function registerRefreshJti(userId: string, jti: string): Promise<void> {
  const k = userRefreshSetKey(userId);
  await redis.sadd(k, jti);
  await redis.expire(k, REFRESH_TTL_SECONDS);
}

export async function revokeAllUserRefreshTokens(userId: string): Promise<void> {
  const k = userRefreshSetKey(userId);
  const jtis = await redis.smembers(k);
  if (jtis.length > 0) {
    const pipe = redis.pipeline();
    for (const jti of jtis) pipe.set(jtiKey(jti), "revoked", "EX", REFRESH_TTL_SECONDS);
    pipe.del(k);
    await pipe.exec();
  }
}

export async function isJtiRevoked(jti: string): Promise<boolean> {
  return (await redis.get(jtiKey(jti))) !== null;
}
