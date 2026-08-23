# OAuth → MCP test checklist

1. GET `/.well-known/oauth-authorization-server`
2. POST `/oauth/register` with ChatGPT redirect_uris.
3. Open `/oauth/auth` with response_type=code and PKCE S256.
4. Submit `/oauth/login` using `TERMINAL_PASSWORD`.
5. Confirm log: `[OAUTH] Authorization approved`.
6. Confirm next log: `[OAUTH] Token request grant_type=authorization_code`.
7. Confirm next log: `[OAUTH] Access token issued`.
8. Send Bearer token to `/mcp/sse`.
9. MCP client should receive the `endpoint` event.
10. POST JSON-RPC messages to `/mcp/message?sessionId=...`.
11. Verify `initialize`, `tools/list`, and `tools/call`.

Required Koyeb environment variables:
- `TERMINAL_PASSWORD`
- `SESSION_SECRET`
- `APP_URL` set to the public HTTPS Koyeb URL

Do not expose `TERMINAL_PASSWORD` or `SESSION_SECRET` in source control or logs.