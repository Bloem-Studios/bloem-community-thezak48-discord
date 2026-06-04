# silo-plugin-discord

> **WIP:** This plugin is currently a work in progress. Official builds/releases are planned for a future update.

Discord OAuth2 auth provider plugin for [Silo Server](https://github.com/Silo-Server/silo-server).

## What it provides

- `auth_provider.v1` capability in `oauth2` mode
- Discord OAuth authorize + code exchange flow
- Optional refresh-session support when Discord returns a refresh token

## Prerequisites

Before setup, confirm:

1. Your Silo server is reachable at a stable public URL.
2. `SILO_PUBLIC_URL` is set to that same URL in the Silo server environment.
3. You can access Silo admin and plugin repositories.
4. You have a Discord application in <https://discord.com/developers/applications>.

## Quick start

1. Build this plugin binary:
   ```bash
   make build
   ```
2. Add/install the plugin in Silo from your plugin repository.
3. Enable the installation.
4. Set plugin global config values (`discord_client_id`, `discord_client_secret`, optional scopes/base URL).
5. Enable auth binding for capability `discord`.
6. Add Discord callback URL using your installation ID:
   `https://<your-public-silo-url>/api/v1/auth/oauth/<installation_id>/callback`
7. Verify OAuth init endpoint returns `302` to Discord.

## Build output

The plugin binary is produced as:

`./plugin`

## Silo-side setup

### 1) Install and enable the plugin

Install `silo-plugin-discord` from your configured plugin repository, then enable the installation in Silo admin.

### 2) Find installation ID

You need the numeric installation ID for callback URLs and OAuth endpoints. You can get it from:

- Silo admin URL path: `/admin/plugins/installations/{id}`
- Admin API: `GET /api/v1/admin/plugins/installations`

### 3) Configure plugin global settings

Set these global config values:

1. `discord_client_id` (required)
2. `discord_client_secret` (required)
3. `discord_scopes` (optional, default: `identify email`)
4. `discord_base_url` (optional, default: `https://discord.com`)

### 4) Enable auth binding

Bind capability `discord` under plugin auth bindings, enable it, and set `auto_provision` according to your desired user onboarding behavior.

## Discord app setup

1. Open <https://discord.com/developers/applications>.
2. Create a new app (or open an existing one).
3. Go to **OAuth2**.
4. Under **Redirects**, add:
   `https://<your-public-silo-url>/api/v1/auth/oauth/<installation_id>/callback`
5. Copy **Client ID** into Silo `discord_client_id`.
6. Copy **Client Secret** into Silo `discord_client_secret`.
7. Set scopes (minimum: `identify`; recommended: `identify email`) and store as a space-separated value in `discord_scopes`.

## Verification

After configuration, confirm these checks:

1. `GET /api/v1/auth/providers` includes your plugin provider (for example `plugin:<id>:discord`, mode `oauth`).
2. `POST /api/v1/auth/oauth/<installation_id>/init` returns `302 Found`.
3. `Location` header points to Discord OAuth authorize URL and contains the expected callback URL.

Example:

```bash
curl -i -X POST http://<silo-host>/api/v1/auth/oauth/<installation_id>/init
```

## Troubleshooting

### `POST /api/v1/auth/oauth/<installation_id>/init` returns 404

- **Cause:** Silo OAuth routes are not mounted because `SILO_PUBLIC_URL` is missing/unset.
- **Fix:** Set `SILO_PUBLIC_URL` to your externally reachable Silo URL and restart Silo.

### Discord says redirect URL is invalid/mismatched

- **Cause:** Callback in Discord app does not exactly match Silo callback URL (scheme/host/path/port mismatch).
- **Fix:** Ensure both sides match exactly:
  `https://<your-public-silo-url>/api/v1/auth/oauth/<installation_id>/callback`

## Security note

If client secrets or admin/user tokens are exposed in logs, terminal history, or chat, rotate them immediately.
