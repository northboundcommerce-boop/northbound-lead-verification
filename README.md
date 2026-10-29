# Northbound verification endpoint repair
Replace the Vercel project's `api/` files and `package.json` with these files, then deploy to production.
Required existing environment variables: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, TURNSTILE_SECRET_KEY, QUO_API_KEY.
Optional: QUO_PHONE_NUMBER_ID (if Quo requires a phone-number ID rather than an E.164 sender).
IMPORTANT: Verify the Quo sender and API key format against the connected Quo account before live SMS testing.
Health endpoint: /api/health. Do not turn on Meta ads until a full verified lead submission succeeds.
