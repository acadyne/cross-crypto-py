from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generateRSAKeys(bits=4096):
    try:        
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        public_key = private_key.public_key()
        
        return {
            "privateKey": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            "publicKey": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        }
    except Exception as e:
        print("Error en generateRSAKeys:", str(e))
        raise    