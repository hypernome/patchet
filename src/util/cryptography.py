from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
import base64, os, glob

class AgentKeyManager:
    def __init__(self):
        self.key_home_dir = "../.runtime"
        self.private_key_filepaths = glob.glob(f"{self.key_home_dir}/*-pop-privatekey.pem")
        self.agent_keys: dict[str, dict] = {}  
        for filepath in self.private_key_filepaths:
            try: 
                with open(filepath, 'r') as f: 
                    file_name = os.path.basename(filepath)
                    agent_id = file_name.split('-')[0]
                    self.agent_keys[agent_id] = {
                        'private_key': self.load_private_key(agent_id), 
                        'public_key_pem': self.load_public_key(agent_id).public_bytes(
                            encoding=serialization.Encoding.PEM, 
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode('utf-8')
                    }
            except Exception as e: 
                pass
    
    def generate_keys_for_agent(self, agent_id: str):
        """
        Generate RSA key pair for agent
        """
        
        if agent_id in self.agent_keys: 
            return self.agent_keys[agent_id]['public_key_pem']
        
        private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_pem = self.save_key(agent_id, private_key)
        public_key_pem = public_pem.decode('utf-8')
        
        self.agent_keys[agent_id] = {
            'private_key': private_key,
            'public_key_pem': public_key_pem
        }
        
        return public_key_pem
    
    def get_public_key_jwk(self, agent_id: str) -> dict:
        """
        Convert public key to JWK format for cnf claim
        """
        public_key = self.agent_keys[agent_id]['private_key'].public_key()
        
        # Get public key components
        public_numbers = public_key.public_numbers()
        
        # Convert to JWK format
        def int_to_base64url(val):
            byte_length = (val.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(val.to_bytes(byte_length, 'big')).decode('ascii').rstrip('=')
        
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": int_to_base64url(public_numbers.n),
            "e": int_to_base64url(public_numbers.e)
        }
    
    def save_key(self, agent_id: str, private_key: RSAPrivateKey):
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
        private_filepath = f"{self.key_home_dir}/{agent_id}-pop-privatekey.pem"
        with open(private_filepath, 'wb') as private_f:
            private_f.write(private_pem)
    
        public_key: RSAPublicKey = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_filepath = f"{self.key_home_dir}/{agent_id}-pop-publickey.pem"
        with open(public_filepath, 'wb') as public_f:
            public_f.write(public_pem)
        
        return public_pem
        
    def load_private_key(self, agent_id: str) -> RSAPrivateKey:
        filepath = f"{self.key_home_dir}/{agent_id}-pop-privatekey.pem"
        with open(filepath, 'rb') as f:
            private_key: RSAPrivateKey = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        return private_key
    
    def load_public_key(self, agent_id: str) -> RSAPublicKey:
        filepath = f"{self.key_home_dir}/{agent_id}-pop-publickey.pem"
        
        with open(filepath, 'rb') as f:
            public_key: RSAPublicKey = serialization.load_pem_public_key(
                f.read()
            )
        return public_key
    
