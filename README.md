# Cross Crypto Py ![PyPI](https://img.shields.io/pypi/v/cross-crypto-py) ![License](https://img.shields.io/github/license/acadyne/cross-crypto-py) ![Python Versions](https://img.shields.io/pypi/pyversions/cross-crypto-py) ![Build](https://img.shields.io/badge/build-passing-brightgreen)

**Cifrado híbrido interoperable entre Python y TypeScript, con diseño compatible para Rust.**

Cross Crypto Py combina:

- **AES-256-GCM** para cifrado autenticado.
- **RSA-OAEP** para envolver la clave simétrica.
- **RSA-OAEP SHA-256 por defecto desde v2.0.0**.
- Compatibilidad legacy con **RSA-OAEP SHA-1**.
- Soporte opcional para **AAD**.
- Firmas **Ed25519** para autenticidad de payloads JSON.
- Soporte para JSON, binario, archivos, carpetas y objetos serializados con `dill`.
- Stream portable `.ccenc` para archivos grandes.

---

## Introducción

**Cross Crypto Py** es una librería de cifrado híbrido diseñada para interoperar entre distintos lenguajes, especialmente **Python ↔ TypeScript**, con un contrato de formato pensado para extenderse a Rust.

Permite cifrar datos en un lenguaje y descifrarlos en otro manteniendo un formato de sobre estable.

Para datos en memoria, el sobre cifrado usa JSON:

```json
{
  "encryptedKey": "...",
  "encryptedData": "...",
  "nonce": "...",
  "tag": "...",
  "mode": "json",
  "aad": "none",
  "oaepHash": "sha256"
}
```

Desde la versión `2.0.0`, los paquetes cifrados incluyen el campo `oaepHash`:

```json
{
  "oaepHash": "sha256"
}
```

Esto permite que el receptor sepa con qué hash OAEP debe descifrar la clave simétrica.

Para stream, desde `2.0.0`, se usa un archivo binario portable `.ccenc` con header embebido.

## Nota importante sobre seguridad

Esta librería ofrece cifrado autenticado con **AES-GCM** y envoltura de clave con **RSA-OAEP**.

Eso significa:

- El contenido viaja cifrado.
- Cualquier modificación del `ciphertext`, `tag`, `AAD` o clave cifrada debe fallar.
- Solo quien tenga la clave privada RSA puede descifrar.
- Con **AAD** puedes autenticar metadatos externos sin cifrarlos.
- Con **Ed25519** puedes firmar payloads JSON para verificar identidad/autenticidad del emisor.

Pero:

- No es “seguridad bidireccional” automáticamente si ambas partes no gestionan sus propias claves correctamente.
- No es un protocolo completo de mensajería E2E con doble ratchet, forward secrecy o rotación automática de claves.
- `dill` puede ejecutar código durante deserialización si el payload no es confiable.
- No uses `mode="dill"` con datos de origen no confiable, incluso si están cifrados o firmados.

## Instalación

```bash
pip install cross-crypto-py
```

## Requisitos

- Python ≥ 3.7
- `cryptography`
- `pycryptodome`
- `dill`

## Uso básico: JSON en memoria

```python
from cross_crypto_py import generateRSAKeys, encryptHybrid, decryptHybrid

keys = generateRSAKeys(bits=4096)

public_key = keys["publicKey"]
private_key = keys["privateKey"]

payload = {
    "mensaje": "Hola desde Python",
    "ok": True,
}

encrypted = encryptHybrid(payload, public_key)

print(encrypted["mode"])      # json
print(encrypted["oaepHash"])  # sha256

decrypted = decryptHybrid(encrypted, private_key)

print(decrypted)
```

Salida esperada:

```json
{
  "mensaje": "Hola desde Python",
  "ok": true
}
```

## RSA-OAEP SHA-256 por defecto

Desde `2.0.0`, el default es:

```python
encrypted = encryptHybrid(
    data,
    public_key,
    oaep_hash="sha256",
)
```

Y el descifrado detecta automáticamente el campo `oaepHash` si está presente:

```python
decrypted = decryptHybrid(encrypted, private_key)
```

No necesitas pasar `oaep_hash` manualmente cuando el paquete trae:

```json
{
  "oaepHash": "sha256"
}
```

## Compatibilidad legacy con SHA-1

Versiones anteriores usaban **RSA-OAEP con SHA-1** por compatibilidad con algunas implementaciones.

Para cifrar en modo legacy:

```python
encrypted = encryptHybrid(
    {"legacy": True},
    public_key,
    oaep_hash="sha1",
)
```

Para descifrar paquetes viejos que no traen `oaepHash`:

```python
decrypted = decryptHybrid(
    encrypted_legacy,
    private_key,
    oaep_hash="sha1",
)
```

Si el paquete viejo trae:

```json
{
  "oaepHash": "sha1"
}
```

entonces `decryptHybrid(...)` lo detecta automáticamente.

## Modos soportados

### JSON

```python
encrypted = encryptHybrid(
    {"hello": "world"},
    public_key,
    mode="json",
)

decrypted = decryptHybrid(
    encrypted,
    private_key,
    mode="json",
)
```

### Binario

```python
data = b"\x00\x01\x02hello\xff"

encrypted = encryptHybrid(
    data,
    public_key,
    mode="binary",
)

decrypted = decryptHybrid(
    encrypted,
    private_key,
    mode="binary",
)

assert decrypted == data
```

### Dill

`dill` permite serializar objetos Python, pero no es interoperable con TypeScript/Rust.

Además, deserializar `dill` puede ejecutar código. Úsalo solo con datos confiables y en flujos completamente controlados.

En esta versión, `mode="dill"` espera una firma embebida válida para descifrar correctamente. Para interoperabilidad Python ↔ TypeScript usa `json`, `binary`, archivos ZIP o stream `.ccenc`.

## AAD: datos autenticados no cifrados

Puedes pasar **AAD** para autenticar metadatos externos.

El AAD no se cifra, pero sí queda protegido por el tag **AES-GCM**. Si el receptor usa un AAD diferente, el descifrado falla.

```python
aad = {
    "tenant": "acadyne",
    "purpose": "test",
}

encrypted = encryptHybrid(
    {"msg": "hola"},
    public_key,
    aad=aad,
)

decrypted = decryptHybrid(
    encrypted,
    private_key,
    aad=aad,
)
```

AAD incorrecto:

```python
decryptHybrid(
    encrypted,
    private_key,
    aad={"tenant": "otro"},
)
```

Debe fallar con error de autenticación.

## Cifrado híbrido de archivos y carpetas

`encryptFileHybrid` empaqueta archivos/carpetas en un ZIP y cifra ese ZIP.

Por defecto usa modo no-stream: el ZIP se cifra como binario y se guarda en JSON `.enc.json`.

```python
from cross_crypto_py.file_crypto import encryptFileHybrid, decryptFileHybrid

encrypted = encryptFileHybrid(
    paths=["datos/", "documento.pdf"],
    public_key=public_key,
    save_file=True,
    output_enc="datos.enc.json",
)

output_dir = decryptFileHybrid(
    "datos.enc.json",
    private_key,
    extract_to="datos_descifrados",
)

print("Archivos restaurados en:", output_dir)
```

## Cifrado de archivos con OAEP SHA-256

Por defecto:

```python
encrypted = encryptFileHybrid(
    paths=["datos/"],
    public_key=public_key,
    save_file=True,
    output_enc="datos.enc.json",
)
```

equivale a:

```python
encrypted = encryptFileHybrid(
    paths=["datos/"],
    public_key=public_key,
    save_file=True,
    output_enc="datos.enc.json",
    oaep_hash="sha256",
)
```

Para compatibilidad legacy:

```python
encrypted = encryptFileHybrid(
    paths=["datos/"],
    public_key=public_key,
    save_file=True,
    output_enc="datos_legacy.enc.json",
    oaep_hash="sha1",
)
```

Y para descifrar un paquete viejo sin `oaepHash`:

```python
output_dir = decryptFileHybrid(
    "datos_legacy.enc.json",
    private_key,
    oaep_hash="sha1",
)
```

## Modo streaming portable `.ccenc` para archivos grandes

Desde `2.0.0`, el modo stream produce un archivo binario portable `.ccenc`.

El archivo contiene:

- Magic header `CCRYPT2\n`.
- Longitud del header en 4 bytes big-endian.
- Header JSON embebido con `encryptedKey`, `nonce`, `tag`, `oaepHash`, `streamFormat`, `contentMode`, `aad`, `cipher` y `keyWrap`.
- Ciphertext **AES-GCM** después del header.

```python
from cross_crypto_py import encryptHybrid, decryptHybrid

encrypted = encryptHybrid(
    "video.mp4",
    public_key,
    mode="binary",
    stream=True,
    output_path="video.mp4.ccenc",
)

output_path = decryptHybrid(
    "video.mp4.ccenc",
    private_key,
    stream=True,
    decrypted_output_path="video_restaurado.mp4",
)

print(output_path)
```

También puedes descifrar usando el objeto retornado:

```python
output_path = decryptHybrid(
    encrypted,
    private_key,
    stream=True,
    decrypted_output_path="video_restaurado.mp4",
)
```

También puedes recuperar bytes directamente:

```python
data = decryptHybrid(
    "video.mp4.ccenc",
    private_key,
    stream=True,
    return_bytes=True,
)

assert isinstance(data, bytes)
```

## Archivos/carpetas con stream `.ccenc`

`encryptFileHybrid(..., use_stream=True)` empaqueta primero los archivos en un ZIP y luego cifra ese ZIP como `.ccenc`.

```python
from cross_crypto_py.file_crypto import encryptFileHybrid, decryptFileHybrid

encrypted = encryptFileHybrid(
    paths=["datos/"],
    public_key=public_key,
    output_enc="datos.ccenc",
    use_stream=True,
    attach_metadata=True,
)

print(encrypted["streamFormat"])  # envelope
print(encrypted["encryptedPath"]) # datos.ccenc

output_dir = decryptFileHybrid(
    "datos.ccenc",
    private_key,
    extract_to="datos_descifrados",
)

print(output_dir)
```

En este modo:

- `output_enc` debe apuntar normalmente a `.ccenc`.
- No necesitas `save_file=True`, porque el stream escribe directamente el archivo binario.
- El resultado de `encryptFileHybrid(...)` devuelve metadata del sobre para inspección.

## Firmas Ed25519 para payloads JSON

Además del cifrado, puedes firmar payloads JSON con **Ed25519**.

Esto sirve para verificar que un payload fue emitido por quien posee la clave privada de firma.

```python
from cross_crypto_py import (
    generateEd25519Keys,
    signPayload,
    verifyPayload,
)

keys = generateEd25519Keys()

payload = {
    "user": "fabian",
    "scope": "admin",
}

signature = signPayload(
    payload,
    keys["privateKey"],
    key_id="v1",
)

ok = verifyPayload(
    payload,
    signature,
    keys["publicKey"],
)

print(ok)  # True
```

## Verificación con expiración

Puedes limitar la edad aceptada de una firma:

```python
ok = verifyPayload(
    payload,
    signature,
    keys["publicKey"],
    max_age_seconds=300,
)
```

Esto rechaza firmas demasiado antiguas o con timestamps demasiado adelantados.

## Fingerprint de claves públicas

```python
from cross_crypto_py import fingerprintPublicKey

fp = fingerprintPublicKey(keys["publicKey"])

print(fp)
```

El fingerprint se calcula normalizando la clave pública a DER y aplicando **SHA-256**.

## Interoperabilidad Python ↔ TypeScript

El subconjunto interoperable entre Python y TypeScript es:

- `mode="json"`
- `mode="binary"`
- Archivos/carpetas vía ZIP cifrado
- Stream portable `.ccenc`
- AAD
- OAEP SHA-256 / SHA-1 según `oaepHash`
- Firmas Ed25519 sobre payloads JSON canónicos

`mode="dill"` es solo Python.

### Sobre JSON para datos en memoria

```json
{
  "encryptedKey": "base64",
  "encryptedData": "base64",
  "nonce": "base64",
  "tag": "base64",
  "mode": "json | binary | dill",
  "aad": "present | none",
  "oaepHash": "sha1 | sha256"
}
```

Para interoperabilidad Python ↔ TypeScript, usa normalmente:

```json
{
  "mode": "json | binary"
}
```

### Stream portable `.ccenc`

Para stream portable `.ccenc`, el contrato va embebido dentro del archivo:

```json
{
  "version": 2,
  "format": "cross-crypto-stream",
  "streamFormat": "envelope",
  "cipher": "AES-256-GCM",
  "keyWrap": "RSA-OAEP",
  "encryptedKey": "base64",
  "nonce": "base64",
  "tag": "base64",
  "mode": "stream",
  "contentMode": "binary",
  "aad": "present | none",
  "oaepHash": "sha1 | sha256"
}
```

El formato binario del `.ccenc` es:

```text
CCRYPT2\n
uint32_be(header_json_length)
header_json_utf8
ciphertext
```

Reglas importantes:

- `oaepHash` debe viajar en el sobre o en el header del `.ccenc`.
- Si `aad` es `"present"`, ambos lados deben usar exactamente el mismo AAD.
- JSON cifrado se serializa como UTF-8 compacto, sin espacios innecesarios.
- Las firmas Ed25519 usan JSON canónico con claves ordenadas.
- Binario debe tratarse como bytes crudos, no como texto UTF-8.
- `dill` solo es compatible con Python.
- El stream `.ccenc` no depende de archivos secundarios: header y ciphertext viajan juntos.
- Para stream interoperable Python ↔ TypeScript, usa `contentMode="binary"`.

## Ejemplo de roundtrip SHA-256

```python
from cross_crypto_py import generateRSAKeys, encryptHybrid, decryptHybrid

keys = generateRSAKeys(bits=2048)

encrypted = encryptHybrid(
    {"ok": True},
    keys["publicKey"],
)

assert encrypted["oaepHash"] == "sha256"

decrypted = decryptHybrid(
    encrypted,
    keys["privateKey"],
)

assert decrypted == {"ok": True}
```

## Ejemplo de roundtrip legacy SHA-1

```python
from cross_crypto_py import generateRSAKeys, encryptHybrid, decryptHybrid

keys = generateRSAKeys(bits=2048)

encrypted = encryptHybrid(
    {"legacy": True},
    keys["publicKey"],
    oaep_hash="sha1",
)

assert encrypted["oaepHash"] == "sha1"

decrypted = decryptHybrid(
    encrypted,
    keys["privateKey"],
)

assert decrypted == {"legacy": True}
```

## Características

| Característica                         | Estado                                  |
| -------------------------------------- | --------------------------------------- |
| AES-256-GCM                            | ✅                                      |
| RSA-OAEP SHA-256 por defecto           | ✅                                      |
| RSA-OAEP SHA-1 legacy                  | ✅                                      |
| Campo `oaepHash` en el sobre           | ✅                                      |
| JSON en memoria                        | ✅                                      |
| Binario en memoria                     | ✅                                      |
| Archivos y carpetas vía ZIP            | ✅                                      |
| Modo streaming portable `.ccenc`       | ✅                                      |
| AAD para metadatos autenticados        | ✅                                      |
| Firmas Ed25519 para payloads JSON      | ✅                                      |
| Fingerprint SHA-256 de claves públicas | ✅                                      |
| Stubs `.pyi` incluidos                 | ✅                                      |
| Interoperabilidad Python ↔ TypeScript  | ✅                                      |
| `dill` para objetos Python             | ⚠️ Solo fuentes confiables              |

## Ecosistema Cross-Crypto

- [Cross Crypto Py (Python)](https://github.com/acadyne/cross-crypto-py)
- [Cross Crypto TS (TypeScript)](https://github.com/acadyne/cross-crypto-ts)
- [Cross Crypto RS (Rust)](https://github.com/acadyne/cross-crypto-rs)

## Licencia

MIT © Jose Fabian Soltero Escobar