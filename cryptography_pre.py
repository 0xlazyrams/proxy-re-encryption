"""
Proxy Re-Encryption (PRE) System Implementation

This system allows secure message forwarding between users through a trusted proxy.
The proxy can re-encrypt messages from one user to another without accessing the plaintext content.

Key Components:
1. User Class:
   - Represents a user with email identifier
   - Generates ECC key pair (SECP256R1 curve)
   - Provides public/private key serialization

2. PRESystem Class:
   - Manages user registration and re-encryption keys
   - Implements core PRE operations:
        a) encrypt_message: User encrypts message under their own public key
        b) generate_rekey: Create bidirectional re-encryption keys between users
        c) reencrypt: Transform ciphertext from sender to receiver format
        d) decrypt_message: Receiver decrypts message with their private key

Cryptography Overview:
- ECC (Elliptic Curve Cryptography) for key exchange (ECDH)
- HKDF for key derivation
- AES-GCM for authenticated symmetric encryption
- Bidirectional re-encryption using key pair transformations

Message Flow Example (Alice → Proxy → Bob):
1. Alice encrypts message under HER OWN public key
2. Proxy transforms ciphertext to Bob's format using rekey
3. Bob decrypts message with HIS OWN private key
"""

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

""""1) Generate the private key for user using seeds, in the seeds use mailId and a secret string to generate the keypairs, then there is no need to store the private key."""

class User:
    """Represents a user in the PRE system with cryptographic keys"""
    def __init__(self, email):
        self.email = email
        # Generate ECC key pair using NIST P-256 curve
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
    
    def serialize_public_key(self):
        """Serialize public key to PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def serialize_private_key(self):
        """Serialize private key to PEM format without encryption"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

class PRESystem:
    """Main system implementing Proxy Re-Encryption functionality"""
    def __init__(self):
        # Stores registered users: {email: User}
        self.users = {}
        # Stores re-encryption keys: {(from_email, to_email): key_data}
        self.rekeys = {}
        
    def register_user(self, email):
        """Register a new user in the system"""
        if email in self.users:
            raise ValueError(f"User {email} already registered")
        self.users[email] = User(email)
        return self.users[email]
    
    def get_user(self, email):
        """Retrieve user by email"""
        if email not in self.users:
            raise ValueError(f"User {email} not found")
        return self.users[email]
    
    def generate_rekey(self, from_email, to_email):
        """
        Generate bidirectional re-encryption keys between two users
        Stores:
          - Forward key (from->to): Uses sender's private key and receiver's public key
          - Backward key (to->from): Uses receiver's private key and sender's public key
        """
        user_from = self.get_user(from_email)
        user_to = self.get_user(to_email)
        
        # Create tuple keys for both directions
        key_forward = (from_email, to_email)
        key_backward = (to_email, from_email)
        
        # Store forward rekey (from->to)
        self.rekeys[key_forward] = {
            'from_priv': user_from.serialize_private_key(),
            'to_pub': user_to.serialize_public_key()
        }
        
        # Store backward rekey (to->from)
        self.rekeys[key_backward] = {
            'from_priv': user_to.serialize_private_key(),
            'to_pub': user_from.serialize_public_key()
        }
        
        return self.rekeys[key_forward]
    
    def encrypt_message(self, sender_email, plaintext):
        """
        Encrypt a message under the sender's public key
        Steps:
          1. Generate ephemeral key pair
          2. Compute shared secret: eph_private * sender_public
          3. Derive symmetric key using HKDF
          4. Encrypt with AES-GCM
        Returns: {eph_pub, iv, ciphertext, tag}
        """
        sender = self.get_user(sender_email)
        
        # Generate ephemeral key pair
        eph_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        eph_public = eph_private.public_key()
        
        # Compute shared secret using ECDH
        shared_secret = eph_private.exchange(ec.ECDH(), sender.public_key)
        
        # Derive 256-bit symmetric key using HKDF
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_encryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Encrypt with AES-GCM (authenticated encryption)
        iv = os.urandom(12)  # 96-bit IV for GCM
        encryptor = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Serialize ephemeral public key
        eph_pub_pem = eph_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'eph_pub': eph_pub_pem,
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': encryptor.tag  # Authentication tag
        }
    
    def reencrypt(self, from_email, to_email, cipher_data):
        """
        Re-encrypt ciphertext for a different recipient
        Steps:
          1. Retrieve/generate rekey
          2. Decrypt original message using rekey
          3. Re-encrypt under receiver's public key
        Returns: New ciphertext package for receiver
        """
        # Check if rekey exists, generate if needed
        rekey_id = (from_email, to_email)
        if rekey_id not in self.rekeys:
            self.generate_rekey(from_email, to_email)
        rekey = self.rekeys[rekey_id]
        
        # Deserialize keys from stored rekey
        from_priv = serialization.load_pem_private_key(
            rekey['from_priv'],
            password=None,
            backend=default_backend()
        )
        
        # Deserialize original ephemeral public key
        orig_eph_pub = serialization.load_pem_public_key(
            cipher_data['eph_pub'],
            backend=default_backend()
        )
        
        # Compute original shared secret = from_priv * orig_eph_pub
        orig_shared_secret = from_priv.exchange(ec.ECDH(), orig_eph_pub)
        
        # Derive original symmetric key
        orig_sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_encryption',
            backend=default_backend()
        ).derive(orig_shared_secret)
        
        # Decrypt original message
        decryptor = Cipher(
            algorithms.AES(orig_sym_key),
            modes.GCM(cipher_data['iv'], cipher_data['tag']),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(cipher_data['ciphertext']) + decryptor.finalize()
        
        # Re-encrypt for receiver
        receiver = self.get_user(to_email)
        
        # Generate new ephemeral key pair
        new_eph_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        new_eph_public = new_eph_private.public_key()
        
        # Compute new shared secret = new_eph_private * receiver_public
        new_shared_secret = new_eph_private.exchange(ec.ECDH(), receiver.public_key)
        
        # Derive new symmetric key
        new_sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_reencryption',  # Different context for key derivation
            backend=default_backend()
        ).derive(new_shared_secret)
        
        # Encrypt with AES-GCM
        new_iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(new_sym_key),
            modes.GCM(new_iv),
            backend=default_backend()
        ).encryptor()
        new_ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # Serialize new ephemeral public key
        new_eph_pub_pem = new_eph_public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'eph_pub': new_eph_pub_pem,
            'iv': new_iv,
            'ciphertext': new_ciphertext,
            'tag': encryptor.tag
        }
    
    def decrypt_message(self, receiver_email, cipher_data):
        """
        Decrypt message using receiver's private key
        Steps:
          1. Compute shared secret = receiver_private * eph_pub
          2. Derive symmetric key
          3. Decrypt with AES-GCM
        """
        receiver = self.get_user(receiver_email)
        
        # Deserialize ephemeral public key
        eph_pub = serialization.load_pem_public_key(
            cipher_data['eph_pub'],
            backend=default_backend()
        )
        
        # Compute shared secret = receiver_private * eph_pub
        shared_secret = receiver.private_key.exchange(ec.ECDH(), eph_pub)
        
        # Derive symmetric key
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_reencryption',  # Matches re-encryption context
            backend=default_backend()
        ).derive(shared_secret)
        
        # Decrypt message
        decryptor = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(cipher_data['iv'], cipher_data['tag']),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(cipher_data['ciphertext']) + decryptor.finalize()
        
        return plaintext

# Demonstration of the PRE System
if __name__ == "__main__":
    # Initialize PRE system
    pre = PRESystem()
    
    # Register users
    alice = pre.register_user("alice@example.com")
    bob = pre.register_user("bob@example.com")
    
    print("Users registered successfully")
    print(f"Alice public key: {alice.serialize_public_key()[:50]}...")
    print(f"Bob public key: {bob.serialize_public_key()[:50]}...\n")
    
    # Alice sends a message to Bob
    message = b"Hello Bob, this is a secret message!"
    print(f"Original message: {message.decode()}")
    
    # Step 1: Alice encrypts message under HER OWN public key
    cipher_data = pre.encrypt_message("alice@example.com", message)
    print("\nMessage encrypted by Alice")
    print(f"Encrypted data size: {len(cipher_data['ciphertext'])} bytes")
    
    # Step 2: Proxy re-encrypts the message for Bob
    reencrypted_data = pre.reencrypt("alice@example.com", "bob@example.com", cipher_data)
    print("\nMessage re-encrypted by Proxy")
    print(f"Re-encrypted data size: {len(reencrypted_data['ciphertext'])} bytes")
    
    # Step 3: Bob decrypts the message
    decrypted_message = pre.decrypt_message("bob@example.com", reencrypted_data)
    print(f"\nDecrypted message by Bob: {decrypted_message.decode()}")
    
    # Test bidirectional communication
    print("\nTesting bidirectional communication...")
    
    # Bob sends a message to Alice
    message2 = b"Hello Alice, this is Bob's response!"
    print(f"\nOriginal message: {message2.decode()}")
    
    # Bob encrypts message under HIS OWN public key
    cipher_data2 = pre.encrypt_message("bob@example.com", message2)
    
    # Proxy re-encrypts the message for Alice
    reencrypted_data2 = pre.reencrypt("bob@example.com", "alice@example.com", cipher_data2)
    
    # Alice decrypts the message
    decrypted_message2 = pre.decrypt_message("alice@example.com", reencrypted_data2)
    print(f"Decrypted message by Alice: {decrypted_message2.decode()}")