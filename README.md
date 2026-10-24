# api-gateway

Single entry point of Cuida Tu Agua. Spring Boot 4.1 + Spring Cloud Gateway (WebFlux), port **8080**.

## What it does
- Routes by prefix: `/iam`, `/places`, `/devices`, `/consumption`, `/valve`, `/notifications` (StripPrefix=1).
- Validates the ms-iam JWT (RS256 public key, issuer, expiry, Redis revocation list). Services validate again.
- `/…/api/admin/**` requires the ADMIN role.
- CORS for the web (the `Origin` header is removed before forwarding).
- Rate limit (Redis): auth endpoints 10/min per IP; API 20/s per user.
- `X-Correlation-Id` on every request and one access-log line per request.
- Public, read-only guest links (no token, 2 req/s per IP): `GET /places/api/guest/{token}` and `GET /consumption/api/guest/{token}/consumption`.
- `/*/internal/**`, `/*/actuator/**`, `/*/openapi/**`, `/*/health` → 404.

## Run
```powershell
.\mvnw.cmd spring-boot:run          # needs Redis and ../ms-iam/keys/public.pem
docker compose up --build -d        # alternative
```

## Environment variables
| Variable | Default |
|---|---|
| `IAM_URL` … `NOTIFICATIONS_URL` | `http://localhost:3001` … `3006` |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` |
| `IAM_PUBLIC_KEY` | `file:../ms-iam/keys/public.pem` (public key only) |
| `IAM_JWT_ISSUER` | `https://iam.cuidatuagua.local` |
| `GATEWAY_CORS_ALLOWED_ORIGINS` | `http://localhost:8081,http://localhost:19006` |

## Tests
```powershell
.\mvnw.cmd test
```
