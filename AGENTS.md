# Repository Guidelines

## Project Structure & Module Organization

- `server/index.js` contains the Koa application, middleware, authentication, and API routes.
- `server/data.js` provides the JSON persistence helpers used by the API.
- `public/index.html` is the single-page Vue client, including its HTML, CSS, and browser-side logic.
- `db.json` is the local data store and is written by the server; treat it as runtime state.
- `package.json` and `package-lock.json` define the Node.js dependencies and scripts.

## Build, Test, and Development Commands

Install dependencies with `npm install`. Run the application with:

```bash
npm start       # start the Koa server
npm run dev     # current development command; also starts the Koa server
```

The server listens on port `3000` by default; set `PORT` to override it. There is currently no build step, automated test suite, or lint script. Verify changes manually by starting the server and exercising the UI and relevant `/api/*` endpoints.

## Coding Style & Naming Conventions

Use two-space indentation, semicolons, double-quoted JavaScript strings, and small focused functions, matching the existing CommonJS code. Use `camelCase` for variables and functions, `UPPER_SNAKE_CASE` for constants such as `JWT_SECRET`, and descriptive route names under `/api/`. Keep user-facing text consistent with the existing Simplified Chinese UI. Preserve the existing four-space HTML/CSS indentation and grouped inline styles in `public/index.html`.

## Testing Guidelines

No testing framework or coverage threshold is configured. For each change, manually test login, authenticated API access, subscription/group operations, and persistence when applicable. If adding tests, place server tests under `test/`, use names such as `auth.test.js`, and add an executable `npm test` script.

## Commit & Pull Request Guidelines

Recent commits use short imperative-style subjects, often with Conventional Commit prefixes (`feat:`, `fix:`), and may be written in Chinese (for example, `feat: 加强安全验证`). Keep commits focused and describe the user-visible or technical change. Pull requests should explain the behavior changed, include verification steps, link related issues when available, and attach screenshots for UI changes. Call out any `db.json` format or environment-variable changes explicitly.

## Security & Configuration Tips

Set `JWT_SECRET` and, when needed, `SUBSCRIPTION_UA_SECRET` through the environment rather than relying on defaults. Do not commit real credentials, tokens, or production subscription data. Review authentication and rate-limiting behavior when changing API routes, and avoid exposing sensitive fields in responses or logs.
