import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

def loadPublicKey(PUBLIC_KEY):
    try:        
        """
        Carga la clave pública RSA desde un archivo.
        """
        public_key = RSA.import_key(PUBLIC_KEY)
        return public_key
    except Exception as e:
        print("Error en al cargar la lave publica:", str(e))
        raise

def encryptHybrid(data: dict, PUBLIC_KEY) -> dict:
    try:    
        data_str = json.dumps(data).encode('utf-8')
        aes_key = get_random_bytes(32)
        aes_cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = aes_cipher.encrypt_and_digest(data_str)
        public_key = loadPublicKey(PUBLIC_KEY)
        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_key = rsa_cipher.encrypt(aes_key)
        
        return {
            "encryptedKey": base64.b64encode(encrypted_key).decode('utf-8'),
            "encryptedData": base64.b64encode(ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(aes_cipher.nonce).decode('utf-8'),
            "tag": base64.b64encode(tag).decode('utf-8')
        }
    except Exception as e:
        print("Error en encryptHybrid:", str(e))
        raise