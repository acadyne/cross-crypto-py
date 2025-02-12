import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

def loadPrivateKey(PRIVATE_KEY):
    try:    
        """
        Carga la clave privada RSA.
        """
        private_key = RSA.import_key(PRIVATE_KEY)    
        return private_key
    except Exception as e:
        print("Error al cargar la llave privada:", str(e))
        raise

def decryptHybrid(encrypted_data_json: dict, PRIVATE_KEY: str) -> dict:
    try:
        encrypted_key = encrypted_data_json['encryptedKey']
        
        import re
        if not re.match(r'^[A-Za-z0-9+/=]+$', encrypted_key):
            raise ValueError("EncryptedKey no es Base64 válido")
        
        encrypted_key = base64.b64decode(encrypted_data_json['encryptedKey'])
        ciphertext = base64.b64decode(encrypted_data_json['encryptedData'])
        nonce = base64.b64decode(encrypted_data_json['nonce'])
        tag = base64.b64decode(encrypted_data_json['tag'])
        
        private_key = loadPrivateKey(PRIVATE_KEY)
        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key = rsa_cipher.decrypt(encrypted_key)
        
        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
        
        return json.loads(decrypted_data.decode('utf-8'))

    except Exception as e:
        print("Error en decryptHybrid:", str(e))
        raise