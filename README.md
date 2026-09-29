# Aevo Edge Gateway

The Edge Gateway is the only public Worker allowed to forward gateway-only traffic to the Core API. It adds a request id and an HMAC signature over timestamp, method, path, body hash, and the trusted application code. The Core API must validate freshness, signature, gateway identity, and app context before performing end-user/session authorization; the signature is not an end-user identity.

`AEVO_GATEWAY_SIGNING_SECRET` is a Wrangler secret per environment. It must never be placed in `vars`, GitHub repository variables or source files. Personalized responses are forced to `no-store` at this boundary.

Browser clients use an explicit credentialed CORS allowlist through
`AEVO_ALLOWED_ORIGINS` (comma-separated origins). Never use `*` with session
cookies. Local development falls back to the canonical Aevo Go origin on port
`4330`; staging and production must configure their deployed web origins
explicitly.
