# Attacks

Every offensive feature in jwt-tui maps to a real-world class of bug. This file is the field guide: what it is, what it has cost in the wild, how to use the tool against it, and how a defender stops it for good.

> **Lab use only.** Run only against systems you own or have written authorization to test.

---

## 1. `alg: none` forgery

**What it is.** RFC 7515 permits an "unsigned" JWS — `alg: none`, signature segment empty. Many libraries accept whatever `alg` the token claims and skip signature verification when it says `none`. Capitalization variants (`None`, `NONE`, `nOnE`) bypass naive case-sensitive denylists.

**Real-world impact.** CVE-2015-9235 (`jsonwebtoken` Node), CVE-2018-1000531 (`jjwt`), countless wallet/IAM integrations through 2022. The Auth0 advisory from 2015 catalogues a dozen libraries with the same flaw.

**Use the tool.**
```sh
jwt-tui --lab attack alg-none $TOKEN                  # one variant
jwt-tui --lab attack alg-none $TOKEN --variant all    # all four
```

**Defender's checklist.**
- Always pass an *expected* `alg` to the verifier; never trust the header's claim.
- If your library exposes `none`, disable it explicitly.
- Add a unit test that passes a forged `alg: none` token to the verifier and asserts rejection.

---

## 2. HS / RS algorithm confusion

**What it is.** Verifier configured for RS256 (or other asymmetric algs) but accepts whatever `alg` the header claims. An attacker takes the public key, sets `alg: HS256`, and signs the token using the *bytes of the public key* as the HMAC secret. The verifier hashes the same bytes with the same HMAC and the signature matches.

**Real-world impact.** Auth0, Okta-adjacent services, several enterprise SSO vendors. Reported recurrently since 2016. The pattern is generic enough that every JWT-handling library has had a CVE for it at some point.

**Use the tool.**
```sh
jwt-tui --lab attack hs-confusion $TOKEN \
  --public-key issuer-public.pem \
  --hs HS256

# try every common public-key permutation
jwt-tui --lab attack hs-confusion $TOKEN \
  --public-key issuer-public.pem --all-perms
```

**Defender's checklist.**
- Pin the expected algorithm. Never `alg in {RS256, HS256}`.
- If you must accept multiple algorithms, use *different* keys per algorithm — the public key cannot also be a valid HMAC secret.
- Consider switching to EdDSA, which has no PKCS#1 / SPKI ambiguity.

---

## 3. `kid` injection

**What it is.** The `kid` header is meant to select a key. If your code interpolates it into a SQL query, a filename, a shell command, or an LDAP filter without sanitization, you get the matching injection class — and worse, the attacker often gets to choose the bytes of the HMAC secret used to verify the token.

**Real-world impact.** CVE-2018-0114 (Cisco), generic SQLi in homebrew identity providers. The classic "read `/dev/null` via path traversal → empty HMAC key → forge anything" is shockingly common.

**Use the tool.**
```sh
jwt-tui --lab attack kid                              # show all templates
jwt-tui --lab attack kid --label path-traversal-css   # one
```

The templates printed include path-traversal, SQLi, command-injection, and null-byte-truncation patterns. Drop them into the `kid` header of a forged token (built via `sign` or `alg-none`) and observe the verifier's response.

**Defender's checklist.**
- Allowlist `kid` values; reject anything outside.
- Use parameterized queries / safe filename joins; never pass `kid` to a shell.
- Reject `kid` values containing `..`, NUL bytes, quotes, backticks.

---

## 4. HS secret brute force

**What it is.** HMAC keys for HS256/384/512 are arbitrary byte strings. If yours is `secret`, `password123`, or your service name, an attacker with one signed token can grind through a wordlist offline.

**Real-world impact.** Every CTF, every "we set the secret to the company name" disclosure. Not glamorous, but pervasive.

**Use the tool.**
```sh
jwt-tui --lab attack hs-brute $TOKEN \
  --wordlist rockyou.txt --threads 8

# default cap is 10M attempts; lift it for finite wordlists
jwt-tui --lab attack hs-brute $TOKEN \
  --wordlist huge.txt --unlimited
```

**Defender's checklist.**
- Use 256+ bits of secret entropy. `head -c 32 /dev/urandom | base64` is the right level.
- Rotate on incident. Once a key is in someone's wordlist, it's permanently compromised.
- Prefer asymmetric algs (RS/ES/EdDSA) for cross-service tokens.

---

## 5. `jku` / `x5u` redirection

**What it is.** The `jku` (JSON Web Key Set URL) and `x5u` (X.509 cert chain URL) headers tell the verifier where to fetch the key. Verifiers that fetch *any* URL — instead of allowlisting their issuer's domain — let the attacker host their own JWKS and sign tokens with their own private key.

**Real-world impact.** Several published advisories against on-prem identity providers; routinely surfaces in pentest reports.

**Use the tool.**
```sh
jwt-tui --lab attack jku-redirect $TOKEN \
  --url https://attacker.example/.well-known/jwks.json
```

The output is the unsigned token (replace the trailing `.` with your real signature) plus a sample JWKS. You self-host the JWKS at the URL — the tool intentionally does not run a server.

**Defender's checklist.**
- Allowlist exact `jku`/`x5u` URLs (not just domains).
- Better: do not honor these headers at all. Configure the verifier with the JWKS URL out-of-band.
- If you must follow `jku`, also pin a TLS certificate fingerprint.

---

## References

- [RFC 7515 — JWS](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7519 — JWT](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7638 — JWK Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [Critical vulnerabilities in JSON Web Token libraries — Auth0, 2015](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [JSON Web Tokens (JWT) attacks — PortSwigger Web Security Academy](https://portswigger.net/web-security/jwt)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
