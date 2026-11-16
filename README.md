# Team Task API (Render)

This project exposes team-scoped start/stop controls. The worker is intentionally
a local heartbeat placeholder: it does not connect to Free Fire, send packets,
invite players, or flood any service.

## Deploy
1. Upload these files to a Git repository.
2. Create a Render Web Service from the repository.
3. Set `API_KEY` in Render environment variables.
4. Deploy. Render uses `render.yaml` automatically when Blueprint deployment is selected.

## API
Use header `X-API-Key: YOUR_SECRET` for all endpoints except `/health`.

Start:
`POST /spam=TEAM_CODE`

Stop only that team:
`POST /stop=TEAM_CODE`

REST alternatives:
`POST /teams/TEAM_CODE/start`
`POST /teams/TEAM_CODE/stop`

Status:
`GET /status`

Example:
`curl -X POST -H "X-API-Key: YOUR_SECRET" https://YOUR-SERVICE.onrender.com/spam=TEAM123`

The `/spam=...` route name is retained as a compatibility alias, but it starts
only the safe local heartbeat worker.
