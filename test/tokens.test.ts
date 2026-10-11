import { describe, expect, it } from 'vitest';
import { createAccessToken, createRefreshToken, hashToken, verifyAccessToken, verifyRefreshToken } from '../src/lib/tokens.js';

describe('tokens', () => {
  it('emite e valida tokens de acesso e renovação', () => {
    const accessToken = createAccessToken({ sub: 'user-1', email: 'user@example.com' });
    const refreshToken = createRefreshToken('user-1', 'session-1');

    expect(verifyAccessToken(accessToken)).toMatchObject({ sub: 'user-1', email: 'user@example.com' });
    expect(verifyRefreshToken(refreshToken)).toMatchObject({ sub: 'user-1', sid: 'session-1' });
    expect(hashToken(refreshToken)).not.toBe(refreshToken);
  });
});
