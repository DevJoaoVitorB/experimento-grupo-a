import { createHash, randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

export interface AccessTokenPayload {
  sub: string;
  email: string;
}

export interface RefreshTokenPayload {
  sub: string;
  sid: string;
  jti: string;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function createAccessToken(user: AccessTokenPayload): string {
  return jwt.sign({ email: user.email }, env.JWT_ACCESS_SECRET, {
    subject: user.sub,
    expiresIn: env.ACCESS_TOKEN_TTL as jwt.SignOptions['expiresIn']
  });
}

export function createRefreshToken(userId: string, sessionId: string): string {
  return jwt.sign({ sid: sessionId, jti: randomUUID() }, env.JWT_REFRESH_SECRET, {
    subject: userId,
    expiresIn: `${env.REFRESH_TOKEN_TTL_DAYS}d`
  });
}

export function verifyAccessToken(token: string): AccessTokenPayload {
  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET);
  if (typeof payload === 'string' || !payload.sub || typeof payload.email !== 'string') {
    throw new jwt.JsonWebTokenError('Token inválido');
  }
  return { sub: payload.sub, email: payload.email };
}

export function verifyRefreshToken(token: string): RefreshTokenPayload {
  const payload = jwt.verify(token, env.JWT_REFRESH_SECRET);
  if (typeof payload === 'string' || !payload.sub || typeof payload.sid !== 'string' || typeof payload.jti !== 'string') {
    throw new jwt.JsonWebTokenError('Token inválido');
  }
  return { sub: payload.sub, sid: payload.sid, jti: payload.jti };
}
