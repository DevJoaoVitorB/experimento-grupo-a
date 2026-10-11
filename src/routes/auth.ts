import { compare, hash } from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { env } from '../config/env.js';
import { authenticate } from '../middlewares/auth.js';
import { prisma } from '../lib/prisma.js';
import { createAccessToken, createRefreshToken, hashToken, verifyRefreshToken } from '../lib/tokens.js';

const router = Router();
const credentialsSchema = z.object({
  email: z.string().trim().email('E-mail inválido.').max(254).transform((value) => value.toLowerCase()),
  password: z.string().min(8, 'A senha deve ter pelo menos 8 caracteres.').max(72)
});
const registerSchema = credentialsSchema.extend({
  name: z.string().trim().min(1, 'Nome é obrigatório.').max(100)
});
const refreshSchema = z.object({ refreshToken: z.string().min(1) });

function publicUser(user: { id: string; name: string; email: string; createdAt: Date; updatedAt: Date }) {
  return user;
}

async function startSession(user: { id: string; email: string }) {
  const session = await prisma.refreshSession.create({
    data: {
      tokenHash: `pending:${randomUUID()}`,
      expiresAt: new Date(Date.now() + env.REFRESH_TOKEN_TTL_DAYS * 86_400_000),
      userId: user.id
    }
  });
  const refreshToken = createRefreshToken(user.id, session.id);
  await prisma.refreshSession.update({ where: { id: session.id }, data: { tokenHash: hashToken(refreshToken) } });
  return { accessToken: createAccessToken({ sub: user.id, email: user.email }), refreshToken };
}

router.post('/register', async (request, response, next) => {
  try {
    const data = registerSchema.parse(request.body);
    const exists = await prisma.user.findUnique({ where: { email: data.email } });
    if (exists) return response.status(409).json({ error: 'Já existe um usuário com este e-mail.' });

    const user = await prisma.user.create({
      data: { name: data.name, email: data.email, passwordHash: await hash(data.password, 12) },
      select: { id: true, name: true, email: true, createdAt: true, updatedAt: true }
    });
    return response.status(201).json({ user: publicUser(user) });
  } catch (error) { next(error); }
});

router.post('/login', async (request, response, next) => {
  try {
    const data = credentialsSchema.parse(request.body);
    const user = await prisma.user.findUnique({ where: { email: data.email } });
    if (!user || !(await compare(data.password, user.passwordHash))) {
      return response.status(401).json({ error: 'E-mail ou senha inválidos.' });
    }
    const tokens = await startSession(user);
    return response.json({ user: publicUser(user), ...tokens });
  } catch (error) { next(error); }
});

router.post('/refresh', async (request, response, next) => {
  try {
    const { refreshToken } = refreshSchema.parse(request.body);
    const payload = verifyRefreshToken(refreshToken);
    const session = await prisma.refreshSession.findUnique({ where: { id: payload.sid }, include: { user: true } });
    if (!session || session.userId !== payload.sub || session.revokedAt || session.expiresAt <= new Date() || session.tokenHash !== hashToken(refreshToken)) {
      return response.status(401).json({ error: 'Refresh token inválido ou expirado.' });
    }

    await prisma.refreshSession.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
    const tokens = await startSession(session.user);
    return response.json({ ...tokens });
  } catch (error) {
    if (error instanceof z.ZodError) return next(error);
    return response.status(401).json({ error: 'Refresh token inválido ou expirado.' });
  }
});

router.post('/logout', authenticate, async (request, response, next) => {
  try {
    const { refreshToken } = refreshSchema.parse(request.body);
    const payload = verifyRefreshToken(refreshToken);
    if (payload.sub !== request.user!.id) return response.status(403).json({ error: 'Sem permissão para encerrar esta sessão.' });
    const session = await prisma.refreshSession.findUnique({ where: { id: payload.sid } });
    if (session && session.userId === request.user!.id && session.tokenHash === hashToken(refreshToken) && !session.revokedAt) {
      await prisma.refreshSession.update({ where: { id: session.id }, data: { revokedAt: new Date() } });
    }
    return response.status(204).send();
  } catch (error) { next(error); }
});

router.get('/me', authenticate, (request, response) => response.json({ user: request.user }));

export { router as authRouter };
