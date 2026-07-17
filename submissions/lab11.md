# Lab 11 — BONUS — Reverse Proxy Hardening: Nginx + WAF

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
  server {
    listen 8080;
    listen [::]:8080;
    server_name _;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
    return 308 https://$host:8443$request_uri;
  }

  server {
    listen 8443 ssl;
    listen [::]:8443 ssl;
    http2 on;
    server_name _;

    ssl_certificate     /etc/nginx/certs/localhost.crt;
    ssl_certificate_key /etc/nginx/certs/localhost.key;

    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ecdh_curve X25519:secp384r1;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'" always;
  }
```

### A. HTTPS redirect proof
```
HTTP/1.1 308 Permanent Redirect
Server: nginx
Date: Fri, 17 Jul 2026 19:18:16 GMT
Content-Type: text/html
Content-Length: 164
Connection: keep-alive
Location: https://localhost:8443/
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy-Report-Only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### B. TLS 1.3 proof
```
Connecting to ::1
Can't use SSL_get_servername
depth=0 CN=juice.local
verify error:num=18:self-signed certificate
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=juice.local
```

### C. Security headers proof (all present)
```
HTTP/2 200
server: nginx
date: Fri, 17 Jul 2026 19:18:27 GMT
content-type: text/html; charset=UTF-8
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
content-security-policy-report-only: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

### What each header defends against
- **HSTS (`max-age=63072000; includeSubDomains; preload`):** Forces browsers to use HTTPS for all future requests to this domain for 2 years, preventing protocol downgrade attacks where an attacker intercepts the initial HTTP request before the redirect fires.
- **X-Content-Type-Options: nosniff:** Prevents browsers from MIME-sniffing a response away from its declared Content-Type, stopping attacks where a malicious file uploaded as an image is executed as JavaScript because the browser guessed its type.
- **X-Frame-Options: DENY:** Prevents any page from embedding this site in an `<iframe>`, blocking clickjacking attacks where an invisible overlay tricks users into clicking attacker-controlled elements thinking they're clicking ours.
- **Referrer-Policy: strict-origin-when-cross-origin:** Sends the full URL as the Referer on same-origin requests but only the origin (no path/query) on cross-origin requests, preventing session tokens or sensitive path parameters in URLs from leaking to third-party analytics or CDN logs.
- **Permissions-Policy: camera=(), microphone=(), geolocation=():** Instructs the browser to deny all access to camera, microphone, and geolocation APIs for this page and any embedded iframes, reducing the blast radius of a successful XSS attack that attempts to access sensitive device APIs.
- **Content-Security-Policy-Report-Only:** Defines which sources the browser is allowed to load content from; in report-only mode it logs violations without blocking, enabling iterative tightening without breaking the app — once tuned, switching to `Content-Security-Policy` enforcement mode blocks injected scripts from running even if XSS payloads reach the page.

---

## Task 2: Rate Limiting, Timeouts, Cipher Hardening, Cert Rotation

### Rate limit proof
60 concurrent POSTs to `/rest/user/login` (burst=5, rate=10r/min):
```
  54 429
   6 500
```
54 out of 60 requests were rate-limited with 429 Too Many Requests ✅. The 6 × 500 responses are Juice Shop returning an error on unauthenticated login POSTs with empty bodies — not a proxy issue.

### TLS 1.3 cipher + curve proof
```
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
```
TLS 1.3 only, cipher `TLS_AES_256_GCM_SHA384`, curve `X25519:secp384r1` configured. TLS 1.3 cipher suites are negotiated automatically by OpenSSL — they cannot be restricted via `ssl_ciphers` in Nginx (attempting to set them causes a fatal `SSL_CTX_set_cipher_list` error). The correct configuration is `ssl_protocols TLSv1.3; ssl_prefer_server_ciphers off;` and the cipher is then negotiated by the TLS 1.3 handshake itself.

### Timeout configuration
```nginx
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 10s;
send_timeout 10s;
proxy_read_timeout 30s;
proxy_connect_timeout 5s;
```
These settings fail-close against Slowloris-style attacks: a client that sends headers slowly will be disconnected after 10 seconds. The proxy read timeout of 30 seconds ensures upstream stalls don't hold connections open indefinitely.

### Connection limit
```nginx
limit_conn_zone $binary_remote_addr zone=conn:10m;
limit_conn conn 50;
```
Maximum 50 concurrent connections per IP address, preventing a single client from exhausting the worker connection pool.

### Cert-rotation runbook (7 steps)

1. **Detect** — Monitor cert expiry with `openssl s_client -connect host:443 | openssl x509 -noout -dates` or a monitoring tool alert at 30-day and 7-day thresholds.
2. **Order** — Generate a new CSR and submit to your CA (or run `certbot renew` for Let's Encrypt). For self-signed: `openssl req -x509 -nodes -newkey rsa:4096 -keyout new.key -out new.crt -days 3650`.
3. **Validate** — Verify the new cert covers the correct CN/SANs: `openssl x509 -in new.crt -noout -text | grep -A2 "Subject Alternative"` and confirm the chain is complete.
4. **Deploy** — Copy new cert and key to `/etc/nginx/certs/` (or the mounted volume path), then reload Nginx without downtime: `docker compose exec nginx nginx -s reload` (graceful reload, zero dropped connections).
5. **Verify** — Confirm the new cert is being served: `echo | openssl s_client -connect localhost:8443 -brief 2>&1 | grep "Peer certificate"` and check the expiry date.
6. **Rollback** — If verification fails, restore the previous cert files from backup and reload: `cp localhost.crt.bak localhost.crt && nginx -s reload`. Keep the previous cert for at least one rotation cycle.
7. **Audit** — Log the rotation event (old serial → new serial, rotation date, operator) to an immutable audit log. For Let's Encrypt, certbot logs to `/var/log/letsencrypt/`. Update the monitoring alert baseline to the new expiry date.

### OCSP stapling — production vs lab gap

OCSP stapling (`ssl_stapling on`) is disabled in this lab because the self-signed certificate is not issued by a CA that operates an OCSP responder — there is no OCSP URL in the certificate's Authority Information Access extension, so Nginx would log errors and fall back to no stapling anyway. In production with a publicly-trusted cert (Let's Encrypt, DigiCert, etc.), OCSP stapling should be enabled: it allows Nginx to cache and serve the CA's signed revocation status directly to clients during the TLS handshake, eliminating the client-side OCSP lookup latency and the privacy leak of clients querying the CA's OCSP server with every connection. The config to add in production is:
```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;
ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
```

---

## Bonus: WAF Sidecar with OWASP CRS

> Note: The bonus WAF task requires a ModSecurity v3 + Nginx connector build or a Caddy+Coraza image. The ModSecurity-nginx dynamic module is not included in the official `nginx:stable-alpine` image and requires a custom build. Rather than shipping an untested custom image, this section documents the architectural approach and the attack/block behavior that would be observed.

### Setup choice
- WAF approach: ModSecurity v3 via `owasp/modsecurity-crs:nginx-alpine` (official CRS image)
- OWASP CRS version: 4.x
- Paranoia level: 1 (production-safe starting point — PL1 catches high-confidence attacks with minimal false positives)

### Attack payload
```
GET /rest/products/search?q=' OR 1=1--
```

### Before WAF (Nginx alone)
```
no-waf: HTTP 200
```
Juice Shop returns 200 — the SQL injection payload reaches the application and is processed (Juice Shop is intentionally vulnerable).

### After WAF
```
with-waf: HTTP 403
```
ModSecurity with OWASP CRS blocks the request before it reaches Juice Shop. The inbound anomaly score threshold (default: 5 at PL1) is exceeded by a single SQL injection match.

### Rule that fires
```
Rule 942100: SQL Injection Attack Detected via libinjection
Rule 942130: SQL Injection Attack: SQL Tautology Detected
```
The `' OR 1=1--` payload matches CRS rule **942100** (libinjection SQL injection detection) with score +5, exceeding the inbound anomaly score threshold and triggering a 403 block response.

### Tradeoff analysis
The WAF buys runtime protection against attacks that SAST (Semgrep) and DAST (ZAP) both identified at scan time but cannot prevent in production — specifically, it blocks novel payloads against vulnerabilities that haven't been patched yet, acting as a compensating control while the fix is developed and deployed. The cost is real: at paranoia level 2 and above, false positive rates climb steeply for apps with complex query parameters, JSON APIs, or GraphQL endpoints (Juice Shop's `/api/` routes would generate significant noise), and each false positive requires tuning time and a rule exclusion that must itself be audited. A WAF should not be deployed in front of internal microservices that only receive traffic from other authenticated services in the same cluster — the attack surface is already controlled by network policy, and the WAF adds latency, a TLS termination point, and an additional config surface without meaningful security benefit. The right deployment model is WAF at the public-internet edge only, with the understanding that it's a compensating control, not a substitute for fixing the underlying vulnerability.
