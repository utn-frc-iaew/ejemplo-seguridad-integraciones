# Authorization Code - Backend (BFF)

## Objetivo

Implementar el BFF que realiza el intercambio del authorization code por tokens, mantiene la sesión con cookie HttpOnly y actúa como proxy hacia la API protegida.

## Cómo usar

1. Copiar `.env.example` a `.env` y completar `AUTH0_ISSUER_BASE_URL`, `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `SESSION_SECRET` y `FRONTEND_ORIGIN`.
2. Instalar y ejecutar:

```bash
cd authorization-code/backend
cp .env.example .env
npm install
npm run dev
```

## Endpoints principales

- GET /login -> inicia redirect a Auth0
- GET /callback -> recibe `code` y realiza token exchange
- GET /logout -> destruye la sesión
- GET /me -> información de sesión
- GET /api/students-proxy -> proxy que llama a /rs/students usando el access_token guardado
- GET /rs/students -> recurso protegido (valida token)

## Teoría

- El Authorization Code es el flujo recomendado para aplicaciones con servidor (confidenciales). El código se intercambia por tokens en un backend seguro.
- El patrón BFF evita exponer tokens al navegador y centraliza lógica de autorización.
- En la API (RS) se deben validar firma (RS256), `iss`, `aud` y scopes.
