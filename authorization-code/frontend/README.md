# Authorization Code - Frontend (SPA)

## Objetivo

SPA de ejemplo que actúa como interfaz para el BFF. No almacena tokens; todas las llamadas a la API van a través del backend.

## Cómo usar

1. Copiar `.env.example` a `.env` y ajustar `VITE_SERVER_BASE_URL` si hace falta.
2. Instalar y arrancar:

```bash
cd authorization-code/frontend
cp .env.example .env
npm install
npm run dev
```

## Variables relevantes

- `VITE_SERVER_BASE_URL` — URL del BFF (por ejemplo `http://localhost:4000`).

## Teoría

- La SPA inicia el login pidiendo al BFF que redireccione a Auth0. El BFF gestiona tokens y cookies HttpOnly.
- Evitar almacenar tokens en el cliente; el BFF mejora la seguridad y simplifica el manejo de sesiones.

Teoría (breve)

- La SPA inicia el login pidiendo al BFF que redireccione a Auth0. El BFF gestiona tokens y cookies HttpOnly.
- Evitar almacenar tokens en el cliente; el BFF mejora la seguridad y simplifica el manejo de sesiones.
