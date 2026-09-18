# cross-crypto-py

Implementación Python de **Cross-Crypto Protocol v3**.

> Estado actual: `3.0.0`. Release estable de Cross-Crypto Protocol v3.

## Perfil criptográfico

- JWE JSON Flattened: `RSA-OAEP-256` + `A256GCM`
- JWS JSON Flattened: `EdDSA` con Ed25519
- Base64URL sin padding
- claves públicas SPKI PEM
- claves privadas PKCS#8 PEM
- `kid = base64url(SHA-256(SPKI DER))`
- `kid` es identidad criptográfica, no alias libre: debe decodificar 32 bytes y corresponder a la clave usada
- CCENC v3 para archivos grandes

El core v3 usa `cryptography`. `dill` y `pycryptodome` ya no forman parte del protocolo interoperable.

## Requisitos

- Python >= 3.9.2
- `cryptography >= 45`

## Instalación

Cuando el RC esté publicado:

```bash
pip install "cross-crypto-py==3.0.0"
```

Desde este checkout:

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Dominio JSON interoperable

Los helpers JSON v3 son deliberadamente estrictos para evitar conversiones silenciosas entre Python y JavaScript.

Se rechazan, entre otros:

- `NaN` e infinitos;
- enteros fuera de `±Number.MAX_SAFE_INTEGER`;
- claves de objeto que no sean `str`;
- tuples/objetos Python no pertenecientes al dominio JSON;
- surrogates Unicode aislados;
- estructuras con más de 64 niveles o 100,000 nodos.

Para identificadores, cantidades decimales exactas o enteros mayores que el rango seguro de JavaScript, usa strings y valida el dominio en la aplicación.

## Cifrar JSON

```python
from cross_crypto_py import (
    generate_rsa_key_pair,
    encrypt_json,
    decrypt_json,
)

rsa = generate_rsa_key_pair()

envelope = encrypt_json(
    {"message": "hola", "amount": 42},
    rsa["public_key"],
    aad="route:/api/example",
)

value = decrypt_json(
    envelope,
    rsa["private_key"],
    expected_key_id=rsa["kid"],
    expected_aad="route:/api/example",
)
```

## Firmar y verificar

```python
import time

from cross_crypto_py import (
    generate_ed25519_key_pair,
    sign_json,
    verify_json,
)

ed = generate_ed25519_key_pair()

signed = sign_json(
    {"operation": "example"},
    ed["private_key"],
    key_id=ed["kid"],
    signed_at=int(time.time()),
)

verified = verify_json(
    signed,
    ed["public_key"],
    expected_key_id=ed["kid"],
    max_age_seconds=60,
)
```

`iat`, `exp`, `kid`, `ccv`, `typ` y `cty` quedan protegidos por Ed25519.

## Bytes

```python
from cross_crypto_py import encrypt_bytes, decrypt_bytes

envelope = encrypt_bytes(data, rsa["public_key"])

result = decrypt_bytes(
    envelope,
    rsa["private_key"],
    expected_key_id=rsa["kid"],
)

plaintext = result["plaintext"]
authenticated_header = result["protected_header"]
```

## Archivos grandes — CCENC v3

```python
from cross_crypto_py import encrypt_file, decrypt_file

encrypt_file(
    "input.bin",
    "input.bin.ccenc",
    rsa["public_key"],
)

decrypt_file(
    "input.bin.ccenc",
    "restored.bin",
    rsa["private_key"],
    expected_key_id=rsa["kid"],
)
```

Los adaptadores de filesystem escriben a un temporal y publican el destino final sólo después de completar correctamente la operación.

También existen `encrypt_ccenc_bytes()` y `decrypt_ccenc_bytes()`.

## API principal

### Claves

- `generate_rsa_key_pair(bits=3072)`
- `generate_ed25519_key_pair()`
- `key_id_from_public_key(public_key_pem)`

### Cifrado

- `encrypt_bytes()` / `decrypt_bytes()`
- `encrypt_json()` / `decrypt_json()`
- `encrypt_text()` / `decrypt_text()`

### Firmas

- `sign_bytes()` / `verify_bytes()`
- `sign_json()` / `verify_json()`
- `sign_text()` / `verify_text()`
- `is_valid_signature()`

### CCENC

- `encrypt_file()` / `decrypt_file()`
- `encrypt_ccenc_bytes()` / `decrypt_ccenc_bytes()`
- `read_ccenc_header()` / `read_ccenc_file_header()`

Las funciones `read_*_header()` exponen metadata todavía no autenticada. Úsalas sólo para inspección/selección de clave.

## Errores

Las operaciones fallan con `CrossCryptoError`, que expone `code`.

Códigos del protocolo:

```text
invalid_format
invalid_encoding
unsupported_algorithm
unsupported_version
invalid_key
key_mismatch
authentication_failed
signature_invalid
expired
not_yet_valid
payload_too_large
```

## Estabilidad de API 3.x

La superficie pública candidata a `3.0.0` está congelada y documentada en [`docs/API_STABILITY.md`](docs/API_STABILITY.md). El núcleo portable Python ↔ TypeScript comparte semántica; los adaptadores de archivo (`Python`) y `Blob` (`browser`) permanecen específicos del runtime.

## Seguridad

Cross-Crypto no sustituye TLS, autenticación/autorización, protección del host, almacenamiento seguro de claves ni replay protection de negocio.

## Tests

```bash
python -m unittest discover -s tests -v
```

La suite incluye tests locales y vectores producidos por TypeScript. Las claves de `tests/fixtures` son públicas y sólo sirven para conformidad.

## Licencia

MIT
## Runtimes soportados

La matriz objetivo y la política de compatibilidad están en [`docs/RUNTIME_SUPPORT.md`](docs/RUNTIME_SUPPORT.md). La CI prueba múltiples versiones y mantiene separados los conceptos “compatible por metadata” y “probado por matriz”.



## Release 3.0.0

La preparación del release estable está documentada en:

- [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md)
- [`docs/RELEASE_NOTES_3_0_0.md`](docs/RELEASE_NOTES_3_0_0.md)
- [`docs/PUBLISHING.md`](docs/PUBLISHING.md)

`3.0.0` es la release estable promovida después de completar los gates de release.
