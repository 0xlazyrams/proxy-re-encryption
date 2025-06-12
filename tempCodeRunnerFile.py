import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidTag

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
    """Proxy Re-Encryption System with Group Support"""
    def __init__(self):
        # Hardcoded secret for demo purposes
        self.secret = "supersecretkey1234567890!@#$%^&*()"
        self.key_manager = KeyManager(self.secret)
        self.users = set()
        self.groups = {}  # Dictionary to store groups and their members
        self.messages = {}  # Stores messages (direct and group)
        self.rekeys = {}   # Stores re-encryption keys
    
    def register_user(self, email):
        """Register a new user"""
        if email in self.users:
            raise ValueError("User already registered")
        self.users.add(email)
        return True
    
    def is_registered(self, email):
        """Check if user is registered"""
        return email in self.users
    
    def create_group(self, group_name, members):
        """Create a group with specified members"""
        if group_name in self.groups:
            raise ValueError("Group already exists")
        for member in members:
            if not self.is_registered(member):
                raise ValueError(f"Member {member} not registered")
        self.groups[group_name] = set(members)
        return True
    
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
    
    def send_direct_message(self, sender_email, receiver_email, message):
        """Send a direct message from sender to receiver"""
        # Store original ciphertext for sender
        original_cipher = self.encrypt_message(sender_email, message)
        
        # Re-encrypt for receiver
        reencrypted_cipher = self.reencrypt(sender_email, receiver_email, original_cipher)
        
        # Store message in both formats
        message_id = hashlib.sha256(os.urandom(32)).hexdigest()
        self.messages[message_id] = {
            'type': 'direct',
            'sender': sender_email,
            'receiver': receiver_email,
            'original_cipher': original_cipher,
            'reencrypted_cipher': {receiver_email: reencrypted_cipher}
        }
        
        return message_id
    
    def send_group_message(self, sender_email, group_name, message):
        """Send a message to a group, re-encrypting for all members"""
        if not self.is_registered(sender_email):
            raise ValueError("Sender not registered")
        if group_name not in self.groups:
            raise ValueError("Group does not exist")
        if sender_email not in self.groups[group_name]:
            raise ValueError("Sender not a member of the group")
        
        # Encrypt the message under sender's public key
        original_cipher = self.encrypt_message(sender_email, message)
        
        # Re-encrypt for each group member
        reencrypted_ciphers = {}
        for member in self.groups[group_name]:
            reencrypted_ciphers[member] = self.reencrypt(sender_email, member, original_cipher)
        
        # Store message
        message_id = hashlib.sha256(os.urandom(32)).hexdigest()
        self.messages[message_id] = {
            'type': 'group',
            'sender': sender_email,
            'group': group_name,
            'original_cipher': original_cipher,
            'reencrypted_cipher': reencrypted_ciphers
        }
        
        return message_id

# Test the system
if __name__ == "__main__":
    # Initialize PRE system
    pre = PRESystem()
    
    # Register users
    users = [
        "alice@example.com",
        "bob@example.com",
        "rama@example.com",
        "koti@example.com",
        "sasi@example.com",
        "ramya@example.com",
        "abhi@example.com"
    ]
    for user in users:
        pre.register_user(user)
    
    print("All users registered successfully")
    print(f"Alice public key: {pre.key_manager.serialize_public_key('alice@example.com')[:50]}...")
    print(f"Bob public key: {pre.key_manager.serialize_public_key('bob@example.com')[:50]}...")
    print(f"Rama public key: {pre.key_manager.serialize_public_key('rama@example.com')[:50]}...")
    print(f"Koti public key: {pre.key_manager.serialize_public_key('koti@example.com')[:50]}...")
    print(f"Sasi public key: {pre.key_manager.serialize_public_key('sasi@example.com')[:50]}...")
    print(f"Ramya public key: {pre.key_manager.serialize_public_key('ramya@example.com')[:50]}...")
    print(f"Abhi public key: {pre.key_manager.serialize_public_key('abhi@example.com')[:50]}...\n")
    
    # Create group with Rama, Koti, Sasi, Ramya, Abhi
    group_members = ["rama@example.com", "koti@example.com", "sasi@example.com", "ramya@example.com", "abhi@example.com"]
    pre.create_group("project_team", group_members)
    print("Group 'project_team' created with members:", group_members)
    
    # Test bidirectional communication between Alice and Bob
    print("\nTesting Alice and Bob bidirectional communication...")
    
    # Alice sends a message to Bob
    message1 = b"Hello Bob, this is Alice's confidential message!"
    message_id1 = pre.send_direct_message("alice@example.com", "bob@example.com", message1)
    print(f"\nAlice's message to Bob sent with ID: {message_id1}")
    stored_msg1 = pre.messages[message_id1]
    
    # Alice decrypts her original message
    alice_decrypted1 = pre.decrypt_original("alice@example.com", stored_msg1['original_cipher'])
    print(f"Alice decrypted her original message: {alice_decrypted1.decode()}")
    
    # Bob decrypts the re-encrypted message
    bob_decrypted1 = pre.decrypt_reencrypted("bob@example.com", stored_msg1['reencrypted_cipher']['bob@example.com'])
    print(f"Bob decrypted the re-encrypted message: {bob_decrypted1.decode()}")
    
    # Bob sends a message to Alice
    message2 = b"Hello Alice, this is Bob's secure reply!"
    message_id2 = pre.send_direct_message("bob@example.com", "alice@example.com", message2)
    print(f"\nBob's message to Alice sent with ID: {message_id2}")
    stored_msg2 = pre.messages[message_id2]
    
    # Bob decrypts his original message
    bob_decrypted2 = pre.decrypt_original("bob@example.com", stored_msg2['original_cipher'])
    print(f"Bob decrypted his original message: {bob_decrypted2.decode()}")
    
    # Alice decrypts the re-encrypted message
    alice_decrypted2 = pre.decrypt_reencrypted("alice@example.com", stored_msg2['reencrypted_cipher']['alice@example.com'])
    print(f"Alice decrypted the re-encrypted message: {alice_decrypted2.decode()}")
    
    # Test group communication
    print("\nTesting group communication in 'project_team'...")
    
    # Rama sends a message to the group
    group_message1 = b"Team, this is Rama with project updates!"
    group_message_id1 = pre.send_group_message("rama@example.com", "project_team", group_message1)
    print(f"\nRama's group message sent with ID: {group_message_id1}")
    stored_group_msg1 = pre.messages[group_message_id1]
    
    # All group members try to decrypt Rama's message
    for member in group_members:
        decrypted = pre.decrypt_reencrypted(member, stored_group_msg1['reencrypted_cipher'][member])
        print(f"{member} decrypted Rama's group message: {decrypted.decode()}")
    
    # Koti sends a message to the group
    group_message2 = b"Hi team, Koti here with additional notes!"
    group_message_id2 = pre.send_group_message("koti@example.com", "project_team", group_message2)
    print(f"\nKoti's group message sent with ID: {group_message_id2}")
    stored_group_msg2 = pre.messages[group_message_id2]
    
    # All group members try to decrypt Koti's message
    for member in group_members:
        decrypted = pre.decrypt_reencrypted(member, stored_group_msg2['reencrypted_cipher'][member])
        print(f"{member} decrypted Koti's group message: {decrypted.decode()}")
    
    # Test that Alice and Bob cannot decrypt group messages
    print("\nTesting access control: Alice and Bob attempting to decrypt group messages...")
    try:
        pre.decrypt_reencrypted("alice@example.com", stored_group_msg1['reencrypted_cipher']['rama@example.com'])
        print("Error: Alice should not be able to decrypt group message")
    except InvalidTag:
        print("Alice correctly cannot access group message")
    
    try:
        pre.decrypt_reencrypted("bob@example.com", stored_group_msg2['reencrypted_cipher']['koti@example.com'])
        print("Error: Bob should not be able to decrypt group message")
    except InvalidTag:
        print("Bob correctly cannot access group message")