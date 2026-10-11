import cors from 'cors';
import express, { type NextFunction, type Request, type Response } from 'express';
import { ZodError } from 'zod';
import { env } from './config/env.js';
import { authRouter } from './routes/auth.js';

export const app = express();
app.use(cors({ origin: env.CORS_ORIGIN === '*' ? '*' : env.CORS_ORIGIN.split(',') }));
app.use(express.json({ limit: '20kb' }));
app.get('/health', (_request, response) => response.status(200).json({ status: 'ok' }));
app.use('/auth', authRouter);
app.use((_request, response) => response.status(404).json({ error: 'Rota não encontrada.' }));
app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
  if (error instanceof ZodError) return response.status(400).json({ error: 'Dados inválidos.', details: error.flatten().fieldErrors });
  console.error(error);
  return response.status(500).json({ error: 'Erro interno do servidor.' });
});
