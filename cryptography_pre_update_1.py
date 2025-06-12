import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class KeyManager:
    """Manages deterministic key generation from email and secret"""
    def __init__(self, secret_key):
        self.secret_key = secret_key.encode()
        self.curve = ec.SECP256R1()
        # Hardcoded order for SECP256R1 curve
        self.order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    
    def _derive_private_value(self, email):
        """Derive private key integer from email using HKDF"""
        salt = email.encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'email_to_private_key',
            backend=default_backend()
        )
        key_material = hkdf.derive(self.secret_key)
        private_value = int.from_bytes(key_material, 'big') % (self.order - 1)
        return private_value + 1  # Ensure non-zero
    
    def get_private_key(self, email):
        """Get private key for email"""
        private_value = self._derive_private_value(email)
        return ec.derive_private_key(
            private_value,
            self.curve,
            default_backend()
        )
    
    def get_public_key(self, email):
        """Get public key for email"""
        private_key = self.get_private_key(email)
        return private_key.public_key()
    
    def serialize_public_key(self, email):
        """Serialize public key to PEM format"""
        pub_key = self.get_public_key(email)
        return pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

class PRESystem:
    """Proxy Re-Encryption System"""
    def __init__(self):
        # Hardcoded secret for demo purposes
        self.secret = "supersecretkey1234567890!@#$%^&*()"
        self.key_manager = KeyManager(self.secret)
        self.users = set()
        self.messages = {}
        self.rekeys = {}
    
    def register_user(self, email):
        """Register a new user"""
        if email in self.users:
            raise ValueError("User already registered")
        self.users.add(email)
        return True
    
    def is_registered(self, email):
        """Check if user is registered"""
        return email in self.users
    
    def encrypt_message(self, sender_email, message):
        """Encrypt message under sender's public key"""
        if not self.is_registered(sender_email):
            raise ValueError("Sender not registered")
        
        # Generate ephemeral key pair
        eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        eph_pub = eph_priv.public_key()
        
        # Get sender's public key
        sender_pub = self.key_manager.get_public_key(sender_email)
        
        # Derive shared secret
        shared_secret = eph_priv.exchange(ec.ECDH(), sender_pub)
        
        # Derive symmetric key
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_encryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Encrypt message with AES-GCM
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        # Pad message
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Serialize ephemeral public key
        eph_pub_pem = eph_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'eph_pub': eph_pub_pem,
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': encryptor.tag
        }
    
    def generate_rekey(self, sender_email, receiver_email):
        """Generate re-encryption key"""
        if not self.is_registered(sender_email) or not self.is_registered(receiver_email):
            raise ValueError("User not registered")
        
        # Get sender's private key
        sender_priv = self.key_manager.get_private_key(sender_email)
        
        # Get receiver's public key
        receiver_pub = self.key_manager.get_public_key(receiver_email)
        
        # Create bidirectional key pairs
        key_forward = f"{sender_email}->{receiver_email}"
        key_backward = f"{receiver_email}->{sender_email}"
        
        # Store keys
        self.rekeys[key_forward] = {
            'sender_priv': sender_priv,
            'receiver_pub': receiver_pub
        }
        self.rekeys[key_backward] = {
            'sender_priv': self.key_manager.get_private_key(receiver_email),
            'receiver_pub': self.key_manager.get_public_key(sender_email)
        }
        
        return self.rekeys[key_forward]
    
    def reencrypt(self, sender_email, receiver_email, cipher_data):
        """Re-encrypt ciphertext for receiver"""
        if not self.is_registered(sender_email) or not self.is_registered(receiver_email):
            raise ValueError("User not registered")
        
        # Get re-encryption key
        key = f"{sender_email}->{receiver_email}"
        if key not in self.rekeys:
            self.generate_rekey(sender_email, receiver_email)
        rekey = self.rekeys[key]
        
        # Deserialize ephemeral public key
        eph_pub = serialization.load_pem_public_key(
            cipher_data['eph_pub'],
            backend=default_backend()
        )
        
        # Compute original shared secret
        shared_secret = rekey['sender_priv'].exchange(ec.ECDH(), eph_pub)
        
        # Derive original symmetric key
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_encryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Decrypt original message
        decryptor = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(cipher_data['iv'], cipher_data['tag']),
            backend=default_backend()
        ).decryptor()
        padded_plaintext = decryptor.update(cipher_data['ciphertext']) + decryptor.finalize()
        
        # Unpad message
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        # Re-encrypt for receiver
        receiver_pub = rekey['receiver_pub']
        
        # Generate new ephemeral key pair
        new_eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        new_eph_pub = new_eph_priv.public_key()
        
        # Compute new shared secret
        new_shared_secret = new_eph_priv.exchange(ec.ECDH(), receiver_pub)
        
        # Derive new symmetric key
        new_sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_reencryption',
            backend=default_backend()
        ).derive(new_shared_secret)
        
        # Encrypt with AES-GCM
        new_iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(new_sym_key),
            modes.GCM(new_iv),
            backend=default_backend()
        ).encryptor()
        
        # Pad message
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        new_ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Serialize new ephemeral public key
        new_eph_pub_pem = new_eph_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'eph_pub': new_eph_pub_pem,
            'iv': new_iv,
            'ciphertext': new_ciphertext,
            'tag': encryptor.tag
        }
    
    def decrypt_original(self, email, cipher_data):
        """Decrypt original ciphertext (for sender)"""
        if not self.is_registered(email):
            raise ValueError("User not registered")
        
        # Get user's private key
        private_key = self.key_manager.get_private_key(email)
        
        # Deserialize ephemeral public key
        eph_pub = serialization.load_pem_public_key(
            cipher_data['eph_pub'],
            backend=default_backend()
        )
        
        # Compute shared secret
        shared_secret = private_key.exchange(ec.ECDH(), eph_pub)
        
        # Derive symmetric key
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_encryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Decrypt message
        decryptor = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(cipher_data['iv'], cipher_data['tag']),
            backend=default_backend()
        ).decryptor()
        padded_plaintext = decryptor.update(cipher_data['ciphertext']) + decryptor.finalize()
        
        # Unpad message
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()
    
    def decrypt_reencrypted(self, email, cipher_data):
        """Decrypt re-encrypted ciphertext (for receiver)"""
        if not self.is_registered(email):
            raise ValueError("User not registered")
        
        # Get user's private key
        private_key = self.key_manager.get_private_key(email)
        
        # Deserialize ephemeral public key
        eph_pub = serialization.load_pem_public_key(
            cipher_data['eph_pub'],
            backend=default_backend()
        )
        
        # Compute shared secret
        shared_secret = private_key.exchange(ec.ECDH(), eph_pub)
        
        # Derive symmetric key
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_reencryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Decrypt message
        decryptor = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(cipher_data['iv'], cipher_data['tag']),
            backend=default_backend()
        ).decryptor()
        padded_plaintext = decryptor.update(cipher_data['ciphertext']) + decryptor.finalize()
        
        # Unpad message
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()
    
    def send_message(self, sender_email, receiver_email, message):
        """Complete message sending flow"""
        # Store original ciphertext for sender
        original_cipher = self.encrypt_message(sender_email, message)
        
        # Re-encrypt for receiver
        reencrypted_cipher = self.reencrypt(sender_email, receiver_email, original_cipher)
        
        # Store message in both formats
        message_id = hashlib.sha256(os.urandom(32)).hexdigest()
        self.messages[message_id] = {
            'sender': sender_email,
            'receiver': receiver_email,
            'original_cipher': original_cipher,
            'reencrypted_cipher': reencrypted_cipher
        }
        
        return message_id

# Test the system
if __name__ == "__main__":
    # Initialize PRE system
    pre = PRESystem()
    
    # Register users
    pre.register_user("alice@example.com")
    pre.register_user("bob@example.com")
    
    print("Users registered successfully")
    print(f"Alice public key: {pre.key_manager.serialize_public_key('alice@example.com')[:50]}...")
    print(f"Bob public key: {pre.key_manager.serialize_public_key('bob@example.com')[:50]}...\n")
    
    # Alice sends a message to Bob
    message = b"Hello Bob, this is a confidential message!"
    print(f"Original message: {message.decode()}")
    
    # Complete sending flow
    message_id = pre.send_message("alice@example.com", "bob@example.com", message)
    print(f"\nMessage sent with ID: {message_id}")
    
    # Retrieve stored message
    stored_msg = pre.messages[message_id]
    
    # Alice can decrypt the original ciphertext
    alice_decrypted = pre.decrypt_original(
        "alice@example.com",
        stored_msg['original_cipher']
    )
    print(f"\nAlice decrypted her original message: {alice_decrypted.decode()}")
    
    # Bob can decrypt the re-encrypted ciphertext
    bob_decrypted = pre.decrypt_reencrypted(
        "bob@example.com",
        stored_msg['reencrypted_cipher']
    )
    print(f"Bob decrypted the re-encrypted message: {bob_decrypted.decode()}")
    
    # Test bidirectional communication
    print("\nTesting bidirectional communication...")
    
    # Bob sends a message to Alice
    message2 = b"Hello Alice, this is Bob's secure reply!"
    message_id2 = pre.send_message("bob@example.com", "alice@example.com", message2)
    
    stored_msg2 = pre.messages[message_id2]
    
    # Bob can decrypt his original message
    bob_decrypted2 = pre.decrypt_original(
        "bob@example.com",
        stored_msg2['original_cipher']
    )
    print(f"\nBob decrypted his original message: {bob_decrypted2.decode()}")
    
    # Alice can decrypt the re-encrypted message
    alice_decrypted2 = pre.decrypt_reencrypted(
        "alice@example.com",
        stored_msg2['reencrypted_cipher']
    )
    print(f"Alice decrypted the re-encrypted message: {alice_decrypted2.decode()}")