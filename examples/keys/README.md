# Sample keys

Generate ephemeral keys for the asymmetric algorithms with:

```sh
# ECDSA P-256
jwt-tui sign --alg ES256 --keygen-out es256.pkcs8 --payload '{"sub":"a"}'

# Ed25519
jwt-tui sign --alg EdDSA --keygen-out ed25519.pkcs8 --payload '{"sub":"a"}'
```

RSA keygen is not supported in-binary (ring doesn't expose RSA generation). Use OpenSSL:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -outform DER -out rsa.pkcs8
openssl rsa -in rsa.pkcs8 -inform DER -pubout -outform DER -out rsa.pub.spki
```

Both files are PKCS#8 (private) / SubjectPublicKeyInfo (public) DER, which is what jwt-tui expects.

These keys never leave your machine. Don't commit them.
