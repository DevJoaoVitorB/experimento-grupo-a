#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Configuração
const BASE_URL = (
  process.env.DAST_BASE_URL || 'http://localhost:3000'
).replace(/\/+$/, '');

const REPORT_PATH =
  process.env.DAST_REPORT_PATH ||
  path.join(process.cwd(), 'rs01-rs07-report.json');

const RUN_ID = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
const EMAIL = `dast-${RUN_ID}@example.invalid`;
const PASSWORD = `Dast-${crypto.randomBytes(12).toString('hex')}!`;

const results = [];

let accountCreated = false;
let accessToken = null;
let refreshToken = null;

// Funções auxiliares
function addResult(id, test, status, details) {
  results.push({ id, test, status, details });
}

async function request(method, route, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(`${BASE_URL}${route}`, {
      method,
      headers: {
        ...(options.body !== undefined
          ? { 'Content-Type': 'application/json' }
          : {}),
        ...(options.token
          ? { Authorization: `Bearer ${options.token}` }
          : {})
      },
      body:
        options.body !== undefined
          ? JSON.stringify(options.body)
          : undefined,
      signal: controller.signal
    });

    const text = await response.text();
    let json = null;

    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      // A resposta não precisa ser JSON para ser analisada.
    }

    return {
      status: response.status,
      text,
      json,
      headers: response.headers
    };
  } finally {
    clearTimeout(timer);
  }
}

function tokenFrom(data, names) {
  if (!data || typeof data !== 'object') {
    return null;
  }

  for (const name of names) {
    if (typeof data[name] === 'string' && data[name]) {
      return data[name];
    }
  }

  return (
    tokenFrom(data.data, names) ||
    tokenFrom(data.tokens, names)
  );
}

function leaksInternalDetails(text) {
  return /stack trace|node_modules|\/app\/|\/home\/|prisma\.|SQLITE_ERROR|SQLITE_[A-Z_]+|DATABASE_URL|JWT_(ACCESS|REFRESH)_SECRET/i.test(
    text || ''
  );
}

function isRejectedStatus(status) {
  return [400, 401, 403, 404, 409, 415, 422].includes(status);
}

function isSuccessStatus(status) {
  return status >= 200 && status < 300;
}

function addNotEvaluated(id, test, details) {
  addResult(id, test, 'NOT_EVALUATED', details);
}

// RS01 — Controle de acesso e autorização
async function testRs01() {
  // Uma rota protegida não deve permitir acesso anônimo.
  try {
    const response = await request('GET', '/auth/me');

    addResult(
      'RS01',
      'GET /auth/me sem token é rejeitado',
      [401, 403].includes(response.status)
        ? 'PASS'
        : response.status === 200
          ? 'FAIL'
          : 'NOT_EVALUATED',
      `HTTP ${response.status}; esperado 401 ou 403.`
    );
  } catch (error) {
    addNotEvaluated(
      'RS01',
      'GET /auth/me sem token é rejeitado',
      error.message
    );
  }

  // Um token válido deve permitir acesso à rota protegida.
  if (!accountCreated) {
    addNotEvaluated(
      'RS01',
      'Token válido permite acessar /auth/me',
      'Conta temporária não foi criada.'
    );

    addNotEvaluated(
      'RS01',
      'Refresh token é rejeitado após logout',
      'Conta temporária não foi criada.'
    );

    addNotEvaluated(
      'RS01',
      'IDOR em recursos de outros usuários',
      'A API especificada não possui recurso de negócio pertencente a usuários.'
    );

    return;
  }

  try {
    const login = await request('POST', '/auth/login', {
      body: { email: EMAIL, password: PASSWORD }
    });

    if (isSuccessStatus(login.status)) {
      accessToken = tokenFrom(login.json, [
        'accessToken',
        'access_token',
        'token'
      ]);

      refreshToken = tokenFrom(login.json, [
        'refreshToken',
        'refresh_token'
      ]);
    }

    if (accessToken) {
      const profile = await request('GET', '/auth/me', {
        token: accessToken
      });

      addResult(
        'RS01',
        'Token válido permite acessar /auth/me',
        profile.status === 200
          ? 'PASS'
          : [401, 403].includes(profile.status)
            ? 'FAIL'
            : 'NOT_EVALUATED',
        `Login HTTP ${login.status}; /auth/me HTTP ${profile.status}.`
      );
    } else {
      addNotEvaluated(
        'RS01',
        'Token válido permite acessar /auth/me',
        `Não foi possível extrair o token da resposta de login (HTTP ${login.status}).`
      );
    }

    // A API deve invalidar o refresh token após o logout.
    if (accessToken && refreshToken) {
      const logout = await request('POST', '/auth/logout', {
        token: accessToken,
        body: { refreshToken }
      });

      const refresh = await request('POST', '/auth/refresh', {
        body: { refreshToken }
      });

      addResult(
        'RS01',
        'Refresh token é rejeitado após logout',
        [400, 401, 403].includes(refresh.status)
          ? 'PASS'
          : isSuccessStatus(refresh.status)
            ? 'FAIL'
            : 'NOT_EVALUATED',
        `Logout HTTP ${logout.status}; refresh após logout HTTP ${refresh.status}.`
      );
    } else {
      addNotEvaluated(
        'RS01',
        'Refresh token é rejeitado após logout',
        'Tokens necessários não foram retornados no formato esperado.'
      );
    }
  } catch (error) {
    addNotEvaluated(
      'RS01',
      'Fluxo de login, perfil e logout',
      error.message
    );
  }

  // Não há recurso de negócio pertencente a usuários para testar IDOR.
  addNotEvaluated(
    'RS01',
    'IDOR em recursos de outros usuários',
    'A API especificada não possui recurso de negócio pertencente a usuários.'
  );
}

// RS02 — Configuração segura da aplicação
async function testRs02() {
  try {
    const response = await request('GET', '/health');
    const poweredBy = response.headers.get('x-powered-by');
    const leaked = leaksInternalDetails(response.text);

    addResult(
      'RS02',
      'Health check não expõe detalhes internos',
      leaked || poweredBy ? 'FAIL' : 'PASS',
      `HTTP ${response.status}; detalhes internos: ${
        leaked ? 'detectados' : 'não detectados'
      }; X-Powered-By: ${poweredBy ? 'presente' : 'ausente'}.`
    );
  } catch (error) {
    addNotEvaluated(
      'RS02',
      'Health check não expõe detalhes internos',
      error.message
    );
  }
}

// RS04 — Gerenciamento seguro de credenciais
async function testRs04() {
  const passwordMarker = `Secret-${crypto.randomBytes(8).toString('hex')}`;

  try {
    const response = await request('POST', '/auth/register', {
      body: {
        name: { invalid: true },
        email: 'email-invalido',
        password: passwordMarker
      }
    });

    const passwordExposed = response.text.includes(passwordMarker);

    addResult(
      'RS04',
      'Resposta de cadastro não contém a senha enviada',
      passwordExposed ? 'FAIL' : 'PASS',
      `Senha sentinela ${
        passwordExposed ? 'foi encontrada' : 'não foi encontrada'
      } na resposta.`
    );
  } catch (error) {
    addNotEvaluated(
      'RS04',
      'Resposta de cadastro não contém a senha enviada',
      error.message
    );
  }
}

// RS05 — Validação de entrada
async function testRs05() {
  // Cadastro com tipos e formatos inválidos.
  try {
    const response = await request('POST', '/auth/register', {
      body: {
        name: { invalid: true },
        email: 'email-invalido',
        password: `Invalid-${crypto.randomBytes(8).toString('hex')}!`
      }
    });

    addResult(
      'RS05',
      'Cadastro rejeita payload inválido',
      [200, 201, 202].includes(response.status)
        ? 'FAIL'
        : [400, 409, 415, 422].includes(response.status)
          ? 'PASS'
          : 'NOT_EVALUATED',
      `HTTP ${response.status}.`
    );
  } catch (error) {
    addNotEvaluated(
      'RS05',
      'Cadastro rejeita payload inválido',
      error.message
    );
  }

  // Campos com tipos inesperados não devem ser aceitos como sucesso.
  const invalidPayloads = [
    {
      route: '/auth/login',
      body: {
        email: null,
        password: { invalid: true }
      },
      label: 'Login com tipos inválidos'
    },
    {
      route: '/auth/refresh',
      body: {
        refreshToken: { invalid: true }
      },
      label: 'Refresh com tipo inválido'
    }
  ];

  for (const test of invalidPayloads) {
    try {
      const response = await request('POST', test.route, {
        body: test.body
      });

      addResult(
        'RS05',
        `${test.label} não é aceito como sucesso`,
        isSuccessStatus(response.status) ? 'FAIL' : 'PASS',
        `HTTP ${response.status}.`
      );
    } catch (error) {
      addNotEvaluated(
        'RS05',
        `${test.label} não é aceito como sucesso`,
        error.message
      );
    }
  }
}

// RS06 — Autenticação e proteção de sessão
async function createTemporaryAccount() {
  try {
    const response = await request('POST', '/auth/register', {
      body: {
        name: 'DAST Test User',
        email: EMAIL,
        password: PASSWORD
      }
    });

    accountCreated = [200, 201, 202].includes(response.status);

    if (!accountCreated) {
      addNotEvaluated(
        'RS06',
        'Criar conta temporária para os testes',
        `Cadastro retornou HTTP ${response.status}.`
      );
    }
  } catch (error) {
    addNotEvaluated(
      'RS06',
      'Criar conta temporária para os testes',
      error.message
    );
  }
}

async function testInvalidAccessToken() {
  try {
    const response = await request('GET', '/auth/me', {
      token: 'token.invalido'
    });

    addResult(
      'RS06',
      'Token de acesso inválido é rejeitado',
      [401, 403].includes(response.status)
        ? 'PASS'
        : response.status === 200
          ? 'FAIL'
          : 'NOT_EVALUATED',
      `HTTP ${response.status}; esperado 401 ou 403.`
    );
  } catch (error) {
    addNotEvaluated(
      'RS06',
      'Token de acesso inválido é rejeitado',
      error.message
    );
  }
}

async function testInvalidLogin() {
  try {
    const response = await request('POST', '/auth/login', {
      body: {
        email: `ausente-${RUN_ID}@example.invalid`,
        password: 'Senha-Incorreta-123!'
      }
    });

    addResult(
      'RS06',
      'Login com conta inexistente é rejeitado',
      isRejectedStatus(response.status)
        ? 'PASS'
        : isSuccessStatus(response.status)
          ? 'FAIL'
          : 'NOT_EVALUATED',
      `HTTP ${response.status}.`
    );
  } catch (error) {
    addNotEvaluated(
      'RS06',
      'Login com conta inexistente é rejeitado',
      error.message
    );
  }
}

async function testAccountEnumeration() {
  if (!accountCreated) {
    addNotEvaluated(
      'RS06',
      'Login não revela se a conta existe',
      'Conta temporária não foi criada.'
    );
    return;
  }

  try {
    const knownAccount = await request('POST', '/auth/login', {
      body: {
        email: EMAIL,
        password: `Errada-${crypto.randomBytes(6).toString('hex')}!`
      }
    });

    const unknownAccount = await request('POST', '/auth/login', {
      body: {
        email: `outra-${RUN_ID}@example.invalid`,
        password: `Errada-${crypto.randomBytes(6).toString('hex')}!`
      }
    });

    const normalizeResponse = text =>
      String(text || '').replaceAll(EMAIL, '<email>');

    const responsesMatch =
      knownAccount.status === unknownAccount.status &&
      normalizeResponse(knownAccount.text) ===
        normalizeResponse(unknownAccount.text);

    addResult(
      'RS06',
      'Login não revela se a conta existe',
      responsesMatch ? 'PASS' : 'FAIL',
      `Conta cadastrada: HTTP ${knownAccount.status}; conta inexistente: HTTP ${unknownAccount.status}; respostas ${
        responsesMatch ? 'iguais' : 'diferentes'
      }.`
    );
  } catch (error) {
    addNotEvaluated(
      'RS06',
      'Login não revela se a conta existe',
      error.message
    );
  }
}

function testRateLimiting() {
  addNotEvaluated(
    'RS06',
    'Limitação de tentativas de login',
    'Não foi executado teste de força bruta.'
  );
}

// RS07 — Tratamento seguro de erros
async function testRs07() {
  // Verifica se erros de autenticação expõem detalhes internos.
  try {
    const response = await request('POST', '/auth/login', {
      body: {
        email: `ausente-${RUN_ID}@example.invalid`,
        password: 'Senha-Incorreta-123!'
      }
    });

    const leaked = leaksInternalDetails(response.text);

    addResult(
      'RS07',
      'Erro de login não revela detalhes internos',
      leaked ? 'FAIL' : 'PASS',
      `Detalhes internos ${leaked ? 'detectados' : 'não detectados'}.`
    );
  } catch (error) {
    addNotEvaluated(
      'RS07',
      'Erro de login não revela detalhes internos',
      error.message
    );
  }

  // Erros provocados por payloads inválidos também não devem vazar dados.
  const invalidPayloads = [
    {
      route: '/auth/login',
      body: {
        email: null,
        password: { invalid: true }
      },
      label: 'Login com tipos inválidos'
    },
    {
      route: '/auth/refresh',
      body: {
        refreshToken: { invalid: true }
      },
      label: 'Refresh com tipo inválido'
    }
  ];

  for (const test of invalidPayloads) {
    try {
      const response = await request('POST', test.route, {
        body: test.body
      });

      const leaked = leaksInternalDetails(response.text);

      addResult(
        'RS07',
        `${test.label} não revela detalhes internos`,
        leaked ? 'FAIL' : 'PASS',
        `Detalhes internos ${leaked ? 'detectados' : 'não detectados'}.`
      );
    } catch (error) {
      addNotEvaluated(
        'RS07',
        `${test.label} não revela detalhes internos`,
        error.message
      );
    }
  }
}

// Execução dos testes
async function main() {
  // RS01 — Controle de acesso e autorização.
  await testRs01();

  // RS02 — Configuração segura da aplicação.
  await testRs02();

  // RS04 — Proteção de credenciais.
  await testRs04();

  // RS05 — Validação de entrada.
  await testRs05();

  // RS06 — Autenticação, enumeração e limitação de tentativas.
  await createTemporaryAccount();
  await testInvalidAccessToken();
  await testInvalidLogin();
  await testAccountEnumeration();
  testRateLimiting();

  // RS07 — Tratamento seguro de erros.
  await testRs07();

  writeReport();
}

// Relatório
function writeReport() {
  const summary = {
    passed: results.filter(result => result.status === 'PASS').length,
    failed: results.filter(result => result.status === 'FAIL').length,
    notEvaluated: results.filter(
      result => result.status === 'NOT_EVALUATED'
    ).length
  };

  const report = {
    generatedAt: new Date().toISOString(),
    baseUrl: BASE_URL,
    summary,
    results
  };

  fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });

  fs.writeFileSync(
    REPORT_PATH,
    JSON.stringify(report, null, 2)
  );

  console.log(JSON.stringify(summary, null, 2));
  console.log(`Relatório salvo: ${REPORT_PATH}`);

  process.exitCode = summary.failed > 0 ? 1 : 0;
}

main().catch(error => {
  const report = {
    generatedAt: new Date().toISOString(),
    baseUrl: BASE_URL,
    summary: {
      passed: 0,
      failed: 0,
      notEvaluated: results.length + 1
    },
    error: error.message,
    results
  };

  try {
    fs.mkdirSync(path.dirname(REPORT_PATH), { recursive: true });

    fs.writeFileSync(
      REPORT_PATH,
      JSON.stringify(report, null, 2)
    );
  } catch {
    // Preserva o erro original caso não seja possível salvar o relatório.
  }

  console.error(error);
  process.exitCode = 2;
});