# 🚀 Cross Crypto Py 🐍🔒

![PyPI](https://img.shields.io/pypi/v/cross-crypto-py) ![License](https://img.shields.io/github/license/acadyne/cross-crypto-py) ![Python Versions](https://img.shields.io/pypi/pyversions/cross-crypto-py) ![Build](https://img.shields.io/badge/build-passing-brightgreen)

**Encriptación híbrida segura entre Python, TypeScript y Rust (AES-GCM + RSA-OAEP)**

---

## 📌 Introducción

**Cross Crypto Py** es una librería de encriptación híbrida que combina **AES-GCM** para cifrado simétrico y **RSA-OAEP** para intercambio seguro de claves. Su ventaja clave es la **interoperabilidad total** entre Python, JavaScript/TypeScript y Rust.

> Cifra datos en un lenguaje y descífralos en otro, con soporte para JSON, objetos serializados (`dill`) y archivos binarios (`PDF`, imágenes, etc).

---

## 🛠️ Uso básico (modo JSON)

```python
from cross_crypto_py.keygen import generateRSAKeys
from cross_crypto_py.encrypt import encryptHybrid
from cross_crypto_py.decrypt import decryptHybrid

# 🔑 Generar claves RSA
keys = generateRSAKeys()
publicKey = keys["publicKey"]
privateKey = keys["privateKey"]

# 📩 Datos simples
data = { "mensaje": "Hola AcaDyne desde Python" }

# 🔒 Encriptar con modo JSON (por defecto)
encrypted = encryptHybrid(data, publicKey)
print("🛡️ Encriptado:", encrypted)

# 🔓 Desencriptar
decrypted = decryptHybrid(encrypted, privateKey)
print("✅ Desencriptado:", decrypted)
```

---

## 💡 Uso avanzado

### 🔹 Objetos complejos (`mode="dill"`)

```python
from cross_crypto_py.encrypt import encryptHybrid
from cross_crypto_py.decrypt import decryptHybrid

objeto_complejo = {"clase": MiClase(), "config": {"x": 1}}
encrypted = encryptHybrid(objeto_complejo, publicKey, mode="dill")
decrypted = decryptHybrid(encrypted, privateKey, mode="dill")
```

### 🔸 Archivos binarios (`mode="binary"`)

```python
with open("imagen.png", "rb") as f:
    contenido = f.read()

encrypted = encryptHybrid(contenido, publicKey, mode="binary")
decrypted = decryptHybrid(encrypted, privateKey, mode="binary")

with open("imagen_recuperada.png", "wb") as f:
    f.write(decrypted)
```

---

## 📁 Cifrado híbrido de archivos (`encryptFileHybrid`)

```python
from cross_crypto_py.file_crypto import encryptFileHybrid, decryptFileHybrid

# 🔒 Encriptar uno o varios archivos/carpetas como ZIP
encrypted = encryptFileHybrid(
    paths=["datos/", "documento.pdf"],
    public_key=publicKey,
    save_file=True,
    output_enc="datos.enc"
)

# 🔓 Desencriptar archivo .enc y extraer archivos ZIP
output_dir = decryptFileHybrid("datos.enc", privateKey)
print("Archivos restaurados en:", output_dir)
```

---

## 🧬 Modo streaming para archivos grandes

```python
# Encriptar archivo grande (streaming)
encrypted = encryptHybrid("video.mp4", publicKey, stream=True)

# Desencriptar archivo grande (streaming)
output_path = decryptHybrid(
    encrypted,
    privateKey,
    stream=True,
    decrypted_output_path="video_restaurado.mp4"
)
```

> ✅ Este modo evita cargar el archivo completo en memoria. Ideal para videos, backups, etc.

---

## 🎯 Características

| Característica                                | ✅  |
| --------------------------------------------- | -- |
| Encriptación híbrida AES-GCM + RSA-OAEP       | ✔️ |
| RSA de 4096 bits                              | ✔️ |
| Interoperabilidad: Python ↔ TypeScript ↔ Rust | ✔️ |
| Soporte para objetos (`json`, `dill`)         | ✔️ |
| Soporte para archivos (`binary`)              | ✔️ |
| Cifrado de carpetas y múltiples archivos      | ✔️ |
| Modo streaming para archivos grandes          | ✔️ |
| Encriptación y desencriptación unificadas     | ✔️ |

---

## 📦 Instalación

```bash
pip install cross-crypto-py
```

---

## 🌐 Ecosistema Cross-Crypto

- 🔷 [Cross Crypto Py (Python)](https://github.com/acadyne/cross-crypto-py)
- 🔾 [Cross Crypto TS (TypeScript)](https://github.com/acadyne/cross-crypto-ts)
- 🦀 [Cross Crypto RS (Rust)](https://github.com/acadyne/cross-crypto-rs)

---

## 🧪 Requisitos

- Python ≥ 3.7
- `pycryptodome`, `dill`

---

## 📄 Licencia

MIT © Jose Fabian Soltero Escobar