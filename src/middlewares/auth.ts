import type { NextFunction, Request, Response } from 'express';
import { prisma } from '../lib/prisma.js';
import { verifyAccessToken } from '../lib/tokens.js';

export async function authenticate(request: Request, response: Response, next: NextFunction) {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith('Bearer ')) {
    return response.status(401).json({ error: 'Token de acesso ausente.' });
  }

  try {
    const payload = verifyAccessToken(authorization.slice(7));
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, name: true, email: true, createdAt: true, updatedAt: true }
    });

    if (!user) return response.status(401).json({ error: 'Usuário não encontrado.' });
    request.user = user;
    return next();
  } catch {
    return response.status(401).json({ error: 'Token de acesso inválido ou expirado.' });
  }
}
