# API de autenticação

API REST construída com Express, TypeScript, Prisma e SQLite para cadastro, autenticação e gestão de sessões.

## Execução local

1. Copie `.env.example` para `.env` e substitua os dois segredos JWT por valores distintos, aleatórios e com pelo menos 32 caracteres.
2. Instale as dependências: `npm install`.
3. Crie o banco e aplique as migrações: `npx prisma migrate dev`.
4. Inicie em desenvolvimento: `npm run dev`.

## Rotas

| Método | Rota | Autenticação | Finalidade |
| --- | --- | --- | --- |
| `GET` | `/health` | Não | Estado da API |
| `POST` | `/auth/register` | Não | Cria usuário (`name`, `email`, `password`) |
| `POST` | `/auth/login` | Não | Retorna usuário, access token e refresh token |
| `POST` | `/auth/refresh` | Não | Renova o par de tokens usando `refreshToken` |
| `POST` | `/auth/logout` | Bearer | Revoga a sessão indicada por `refreshToken` |
| `GET` | `/auth/me` | Bearer | Retorna o perfil autenticado |

O access token deve ser enviado em `Authorization: Bearer <accessToken>`. Refresh tokens são armazenados apenas como hash e são rotacionados a cada renovação.

## Docker

Defina `JWT_ACCESS_SECRET` e `JWT_REFRESH_SECRET` no ambiente e execute `docker compose up --build`.
