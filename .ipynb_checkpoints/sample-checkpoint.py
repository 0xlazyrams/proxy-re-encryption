import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class User:
    def __init__(self, email):
        self.email = email
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        
    def get_serialized_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_serialized_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

class PRESystem:
    def __init__(self):
        self.users = {}
        self.rekeys = {}
        
    def register_user(self, email):
        if email in self.users:
            raise ValueError("User already registered")
        self.users[email] = User(email)
        return self.users[email]
    
    def get_user(self, email):
        if email not in self.users:
            raise ValueError("User not found")
        return self.users[email]
    
    def generate_rekey(self, sender_email, receiver_email):
        sender = self.get_user(sender_email)
        receiver = self.get_user(receiver_email)
        
        # Create bidirectional rekey pairs
        key = f"{sender_email}-{receiver_email}"
        self.rekeys[key] = {
            'sender_priv': sender.get_serialized_private_key(),
            'receiver_pub': receiver.get_serialized_public_key()
        }
        return self.rekeys[key]
    
    def encrypt_message(self, sender_email, receiver_email, message):
        sender = self.get_user(sender_email)
        receiver = self.get_user(receiver_email)
        
        # Generate ephemeral key pair
        eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        eph_pub = eph_priv.public_key()
        
        # Derive encryption key
        shared_secret = eph_priv.exchange(ec.ECDH(), receiver.public_key)
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
        ciphertext = encryptor.update(message) + encryptor.finalize()
        
        # Serialize components
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
    
    def reencrypt_message(self, sender_email, receiver_email, cipher_data):
        # Get re-encryption key
        key = f"{sender_email}-{receiver_email}"
        if key not in self.rekeys:
            self.generate_rekey(sender_email, receiver_email)
        rekey = self.rekeys[key]
        
        # Deserialize keys from storage
        sender_priv = serialization.load_pem_private_key(
            rekey['sender_priv'],
            password=None,
            backend=default_backend()
        )
        receiver_pub = serialization.load_pem_public_key(
            rekey['receiver_pub'],
            backend=default_backend()
        )
        
        # Re-encrypt the message
        eph_pub = serialization.load_pem_public_key(
            cipher_data['eph_pub'],
            backend=default_backend()
        )
        
        # Compute new shared secret
        shared_secret = sender_priv.exchange(ec.ECDH(), eph_pub)
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_encryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Create new ephemeral key pair for the receiver
        new_eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        new_eph_pub = new_eph_priv.public_key()
        
        # Compute receiver's shared secret
        new_shared_secret = new_eph_priv.exchange(ec.ECDH(), receiver_pub)
        new_sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_reencryption',
            backend=default_backend()
        ).derive(new_shared_secret)
        
        # Re-encrypt the symmetric key
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(new_sym_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        reencrypted_key = encryptor.update(sym_key) + encryptor.finalize()
        
        return {
            'eph_pub': new_eph_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            'iv': iv,
            'encrypted_key': reencrypted_key,
            'tag': encryptor.tag,
            'original_iv': cipher_data['iv'],
            'original_ciphertext': cipher_data['ciphertext'],
            'original_tag': cipher_data['tag']
        }
    
    def decrypt_message(self, receiver_email, cipher_data):
        receiver = self.get_user(receiver_email)
        
        # Extract components
        eph_pub = serialization.load_pem_public_key(
            cipher_data['eph_pub'],
            backend=default_backend()
        )
        
        # Compute shared secret
        shared_secret = receiver.private_key.exchange(ec.ECDH(), eph_pub)
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pre_reencryption',
            backend=default_backend()
        ).derive(shared_secret)
        
        # Decrypt the symmetric key
        decryptor = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(cipher_data['iv'], cipher_data['tag']),
            backend=default_backend()
        ).decryptor()
        original_sym_key = decryptor.update(cipher_data['encrypted_key']) + decryptor.finalize()
        
        # Decrypt original message
        decryptor = Cipher(
            algorithms.AES(original_sym_key),
            modes.GCM(cipher_data['original_iv'], cipher_data['original_tag']),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(cipher_data['original_ciphertext']) + decryptor.finalize()
        
        return plaintext

# Test the system
if __name__ == "__main__":
    # Initialize PRE system
    pre = PRESystem()
    
    # Register users
    alice = pre.register_user("alice@example.com")
    bob = pre.register_user("bob@example.com")
    
    print("Users registered successfully")
    print(f"Alice public key: {alice.get_serialized_public_key()[:50]}...")
    print(f"Bob public key: {bob.get_serialized_public_key()[:50]}...\n")
    
    # Alice sends a message to Bob
    message = b"Hello Bob, this is a secret message!"
    print(f"Original message: {message.decode()}")
    
    # Step 1: Alice encrypts message for Bob
    cipher_data = pre.encrypt_message("alice@example.com", "bob@example.com", message)
    print("\nMessage encrypted by Alice")
    print(f"Encrypted data size: {len(cipher_data['ciphertext'])} bytes")
    
    # Step 2: Proxy re-encrypts the message
    reencrypted_data = pre.reencrypt_message("alice@example.com", "bob@example.com", cipher_data)
    print("\nMessage re-encrypted by Proxy")
    print(f"Re-encrypted data size: {len(reencrypted_data['encrypted_key'])} bytes key + "
          f"{len(reencrypted_data['original_ciphertext'])} bytes ciphertext")
    
    # Step 3: Bob decrypts the message
    decrypted_message = pre.decrypt_message("bob@example.com", reencrypted_data)
    print(f"\nDecrypted message by Bob: {decrypted_message.decode()}")
    
    # Test bidirectional communication
    print("\nTesting bidirectional communication...")
    
    # Bob sends a message to Alice
    message2 = b"Hello Alice, this is Bob's response!"
    print(f"\nOriginal message: {message2.decode()}")
    
    # Bob encrypts message for Alice
    cipher_data2 = pre.encrypt_message("bob@example.com", "alice@example.com", message2)
    
    # Proxy re-encrypts the message
    reencrypted_data2 = pre.reencrypt_message("bob@example.com", "alice@example.com", cipher_data2)
    
    # Alice decrypts the message
    decrypted_message2 = pre.decrypt_message("alice@example.com", reencrypted_data2)
    print(f"Decrypted message by Alice: {decrypted_message2.decode()}")