# 🚀 Cross Crypto Py 🐍🔒  
**Encriptación híbrida segura entre Python y TypeScript (AES-GCM + RSA-OAEP).**  

## 📌 Introducción  
Cross Crypto Py es una librería de encriptación híbrida que combina **AES-GCM** para cifrado simétrico y **RSA-OAEP** para el intercambio seguro de claves. Su principal ventaja es la interoperabilidad entre **Python** y **TypeScript**, permitiendo cifrar datos en un lenguaje y descifrarlos en el otro sin problemas.  

## 🛠️ Uso  

```python
from cross_crypto.keygen import generateRSAKeys
from cross_crypto.encrypt import encryptHybrid
from cross_crypto.decrypt import decryptHybrid

# 🔑 Generar un par de claves RSA de 4096 bits
keys = generateRSAKeys()
publicKey = keys["publicKey"]
privateKey = keys["privateKey"]

# 📩 Datos a encriptar
data = { "mensaje": "Hola AcaDyne desde Python" }

# 🔒 Encriptación (Cross Crypto)
encrypted = encryptHybrid(data, publicKey)
print("\n🛡️ Datos Encriptados:", encrypted)

# 🔓 Desencriptación (Cross Crypto)
decrypted = decryptHybrid(encrypted, privateKey)
print("\n✅ Datos Desencriptados:", decrypted)
```
## 🎯 Características
✅ Encriptación híbrida: AES-GCM + RSA-OAEP
✅ Interoperabilidad total entre Python y TypeScript
✅ Seguridad avanzada con RSA de 4096 bits
✅ Ideal para cifrado de datos sensibles

## 📦 Instalación

### Python
Instala el paquete con:

```bash
$ pip install cross-crypto-py
```

🔗 [PyPI](https://pypi.org/project/cross-crypto-py/)
🔗 Repositorio de la versión en JavaScript/TypeScript: [Cross Crypto TS](https://github.com/acadyne/cross-crypto-ts)

## 📄 Licencia
Este proyecto se encuentra bajo la licencia MIT.
