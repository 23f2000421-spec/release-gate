# Release Gate

Deterministic policy endpoint for `POST /release-gate`.

## Local test

```sh
npm test
```

## Local Worker

```sh
npm install
npm run dev
```

## Deploy

```sh
npm install
npx wrangler login
npm run deploy
```

Submit JSON in this shape after deploying and pushing this folder to a public
GitHub repository:

```json
{
  "serviceUrl": "https://YOUR_WORKER.YOUR_SUBDOMAIN.workers.dev",
  "workflowUrl": "https://github.com/OWNER/REPO/actions/workflows/release-gate.yml"
}
```
