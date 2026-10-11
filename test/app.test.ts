import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { app } from '../src/app.js';

describe('API', () => {
  it('expõe health check', async () => {
    const response = await request(app).get('/health');
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok' });
  });

  it('protege a rota de perfil sem bearer token', async () => {
    const response = await request(app).get('/auth/me');
    expect(response.status).toBe(401);
  });
});
