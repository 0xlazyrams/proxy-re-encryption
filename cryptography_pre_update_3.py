import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidTag

"""
Step-by-Step Process for Group Creation and Key Encryption
1) Group Creation:
   - A group is created with an admin and initial members using the create_group method.
   - A random 256-bit AES group key is generated to encrypt group messages.
   - The group key is encrypted individually for each member using their public key, ensuring that only they can decrypt it with their private key.
2) Group Key Encryption with User-Specific Encryption:
   - For each member, an ephemeral ECDH key pair is generated, and a shared secret is computed using the member's public key.
   - A symmetric key is derived from this shared secret, and the group key is encrypted with AES-GCM using this symmetric key.
   - This results in a unique encrypted group key for each member, stored in the encrypted_group_keys dictionary under their email.
3) Security Benefits:
   - Each member having a unique encrypted group key means that compromising one member's key does not affect others.
   - When a member is removed or leaves, a new group key is generated and re-encrypted for remaining members, ensuring ex-members cannot decrypt future messages.
   - The use of ephemeral keys provides forward secrecy for the group key encryption.
"""


class KeyManager:
    """Manages deterministic key generation from email and secret"""

    def __init__(self, secret_key):
        self.secret_key = secret_key.encode()
        self.curve = ec.SECP256R1()
        self.order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

    def _derive_private_value(self, email):
        """Derive private key integer from email using HKDF"""
        salt = email.encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"email_to_private_key",
            backend=default_backend(),
        )
        key_material = hkdf.derive(self.secret_key)
        private_value = int.from_bytes(key_material, "big") % (self.order - 1)
        return private_value + 1  # Ensure non-zero

    def get_private_key(self, email):
        """Get private key for email"""
        private_value = self._derive_private_value(email)
        return ec.derive_private_key(private_value, self.curve, default_backend())

    def get_public_key(self, email):
        """Get public key for email"""
        private_key = self.get_private_key(email)
        return private_key.public_key()

    def serialize_public_key(self, email):
        """Serialize public key to PEM format"""
        pub_key = self.get_public_key(email)
        return pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()


class PRESystem:
    """Proxy Re-Encryption System with Optimized Group Messaging"""

    def __init__(self):
        self.secret = "supersecretkey1234567890!@#$%^&*()"
        self.key_manager = KeyManager(self.secret)
        self.users = set()
        self.groups = {}  # {group_name: {'admin': email, 'members': set, 'group_key': bytes, 'encrypted_group_keys': {email: cipher_data}}}
        self.messages = {}  # {message_id: {'type': 'group'|'direct', ...}}
        self.rekeys = {}  # For direct messages

    def register_user(self, email):
        """Register a new user"""
        if email in self.users:
            raise ValueError("User already registered")
        self.users.add(email)
        return True

    def is_registered(self, email):
        """Check if user is registered"""
        return email in self.users

    def create_group(self, group_name, admin_email, initial_members):
        """Create a group with an admin and initial members"""
        if group_name in self.groups:
            raise ValueError("Group already exists")
        if not self.is_registered(admin_email):
            raise ValueError("Admin not registered")
        for member in initial_members:
            if not self.is_registered(member):
                raise ValueError(f"Member {member} not registered")
        group_key = os.urandom(32)  # 256-bit AES key
        encrypted_group_keys = {}
        for member in initial_members:
            encrypted_group_keys[member] = self.encrypt_for_receiver(member, group_key)
        self.groups[group_name] = {
            "admin": admin_email,
            "members": set(initial_members),
            "group_key": group_key,
            "encrypted_group_keys": encrypted_group_keys,
        }
        return True

    def add_member_to_group(self, group_name, admin_email, new_member_email):
        """Admin adds a new member to the group"""
        if group_name not in self.groups:
            raise ValueError("Group does not exist")
        if self.groups[group_name]["admin"] != admin_email:
            raise ValueError("Only the admin can add members")
        if not self.is_registered(new_member_email):
            raise ValueError("New member not registered")
        if new_member_email in self.groups[group_name]["members"]:
            raise ValueError("Member already in group")
        group_key = self.groups[group_name]["group_key"]
        encrypted_group_key = self.encrypt_for_receiver(new_member_email, group_key)
        self.groups[group_name]["members"].add(new_member_email)
        self.groups[group_name]["encrypted_group_keys"][new_member_email] = (
            encrypted_group_key
        )
        return True

    def remove_member_from_group(self, group_name, admin_email, member_email):
        """Admin removes a member from the group"""
        if group_name not in self.groups:
            raise ValueError("Group does not exist")
        if self.groups[group_name]["admin"] != admin_email:
            raise ValueError("Only the admin can remove members")
        if member_email not in self.groups[group_name]["members"]:
            raise ValueError("Member not in group")
        if member_email == admin_email:
            raise ValueError("Admin cannot remove themselves")
        self.groups[group_name]["members"].remove(member_email)
        new_group_key = os.urandom(32)
        for member in self.groups[group_name]["members"]:
            self.groups[group_name]["encrypted_group_keys"][member] = (
                self.encrypt_for_receiver(member, new_group_key)
            )
        self.groups[group_name]["group_key"] = new_group_key
        return True

    def leave_group(self, group_name, member_email):
        """Member leaves the group voluntarily"""
        if group_name not in self.groups:
            raise ValueError("Group does not exist")
        if member_email not in self.groups[group_name]["members"]:
            raise ValueError("Member not in group")
        self.groups[group_name]["members"].remove(member_email)
        new_group_key = os.urandom(32)
        for member in self.groups[group_name]["members"]:
            self.groups[group_name]["encrypted_group_keys"][member] = (
                self.encrypt_for_receiver(member, new_group_key)
            )
        self.generate_group_key = new_group_key
        return True

    def encrypt_for_receiver(self, receiver_email, message):
        """Encrypt a message (e.g., group key) for a specific receiver"""
        eph_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        eph_pub = eph_priv.public_key()
        receiver_pub = self.key_manager.get_public_key(receiver_email)
        shared_secret = eph_priv.exchange(ec.ECDH(), receiver_pub)
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"group_key_encryption",
            backend=default_backend(),
        ).derive(shared_secret)
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(sym_key), modes.GCM(iv), backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        eph_pub_pem = eph_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            "eph_pub": eph_pub_pem,
            "iv": iv,
            "ciphertext": ciphertext,
            "tag": encryptor.tag,
        }

    def decrypt_for_receiver(self, receiver_email, cipher_data):
        """Decrypt a message (e.g., group key) encrypted for the receiver"""
        private_key = self.key_manager.get_private_key(receiver_email)
        eph_pub = serialization.load_pem_public_key(
            cipher_data["eph_pub"], backend=default_backend()
        )
        shared_secret = private_key.exchange(ec.ECDH(), eph_pub)
        sym_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"group_key_encryption",
            backend=default_backend(),
        ).derive(shared_secret)
        decryptor = Cipher(
            algorithms.AES(sym_key),
            modes.GCM(cipher_data["iv"], cipher_data["tag"]),
            backend=default_backend(),
        ).decryptor()
        plaintext = decryptor.update(cipher_data["ciphertext"]) + decryptor.finalize()
        return plaintext

    def encrypt_with_group_key(self, group_key, message):
        """Encrypt a message with the group key using AES-GCM"""
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(group_key), modes.GCM(iv), backend=default_backend()
        ).encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return {"iv": iv, "ciphertext": ciphertext, "tag": encryptor.tag}

    def send_group_message(self, sender_email, group_name, message):
        """Send a message to a group, encrypted with the group key"""
        if not self.is_registered(sender_email):
            raise ValueError("Sender not registered")
        if group_name not in self.groups:
            raise ValueError("Group does not exist")
        if sender_email not in self.groups[group_name]["members"]:
            raise ValueError("Sender not a member of the group")
        group_key = self.groups[group_name]["group_key"]
        cipher_data = self.encrypt_with_group_key(group_key, message)
        message_id = hashlib.sha256(os.urandom(32)).hexdigest()
        self.messages[message_id] = {
            "type": "group",
            "sender": sender_email,
            "group": group_name,
            "ciphertext": cipher_data,
        }
        return message_id

    def decrypt_group_message(self, member_email, message_id):
        """Decrypt a group message for a member"""
        if (
            "type" not in self.messages[message_id]
            or self.messages[message_id]["type"] != "group"
        ):
            raise ValueError("Invalid message type")
        group_name = self.messages[message_id]["group"]
        if member_email not in self.groups[group_name]["members"]:
            raise ValueError("Member not in group")
        encrypted_group_key = self.groups[group_name]["encrypted_group_keys"][
            member_email
        ]
        group_key = self.decrypt_for_receiver(member_email, encrypted_group_key)
        cipher_data = self.messages[message_id]["ciphertext"]
        decryptor = Cipher(
            algorithms.AES(group_key),
            modes.GCM(cipher_data["iv"], cipher_data["tag"]),
            backend=default_backend(),
        ).decryptor()
        padded_plaintext = (
            decryptor.update(cipher_data["ciphertext"]) + decryptor.finalize()
        )
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext


if __name__ == "__main__":
    pre = PRESystem()

    # Register users
    users = [
        "alice@example.com",
        "bob@example.com",
        "rama@example.com",
        "koti@example.com",
        "sasi@example.com",
        "ramya@example.com",
        "abhi@example.com",
    ]
    for user in users:
        pre.register_user(user)

    # Create group with Rama as admin
    group_members = [
        "rama@example.com",
        "koti@example.com",
        "sasi@example.com",
        "ramya@example.com",
        "abhi@example.com",
    ]
    pre.create_group("project_team", "rama@example.com", group_members)
    print(
        "Group 'project_team' created with admin: rama@example.com and members:",
        group_members,
    )

    # Rama sends a message to the group
    message = b"Team, this is Rama with project updates!"
    message_id = pre.send_group_message("rama@example.com", "project_team", message)
    print(f"Rama's group message sent with ID: {message_id}")

    # All group members decrypt the message
    for member in group_members:
        decrypted = pre.decrypt_group_message(member, message_id)
        print(f"{member} decrypted group message: {decrypted.decode()}")

    # Add a new member
    pre.register_user("newmember@example.com")
    pre.add_member_to_group("project_team", "rama@example.com", "newmember@example.com")
    print("Added newmember@example.com to the group")

    # Send another message
    message2 = b"Welcome new member!"
    message_id2 = pre.send_group_message("rama@example.com", "project_team", message2)
    print(f"Rama's second group message sent with ID: {message_id2}")

    # All current members decrypt the second message
    current_members = pre.groups["project_team"]["members"]
    for member in current_members:
        decrypted = pre.decrypt_group_message(member, message_id2)
        print(f"{member} decrypted second group message: {decrypted.decode()}")

    # Remove a member
    pre.remove_member_from_group("project_team", "rama@example.com", "abhi@example.com")
    print("Removed abhi@example.com from the group")

    # Send a third message
    message3 = b"Important update after member removal"
    message_id3 = pre.send_group_message("rama@example.com", "project_team", message3)
    print(f"Rama's third group message sent with ID: {message_id3}")

    # Try to decrypt with removed member (should fail)
    try:
        pre.decrypt_group_message("abhi@example.com", message_id3)
    except ValueError as e:
        print(f"Correctly prevented removed member from decrypting: {e}")

    # Current members decrypt the third message
    for member in pre.groups["project_team"]["members"]:
        decrypted = pre.decrypt_group_message(member, message_id3)
        print(f"{member} decrypted third group message: {decrypted.decode()}")

    # Member leaves the group
    pre.leave_group("project_team", "sasi@example.com")
    print("sasi@example.com has left the group")

    # Send a fourth message
    message4 = b"Update after Sasi left"
    message_id4 = pre.send_group_message("rama@example.com", "project_team", message4)
    print(f"Rama's fourth group message sent with ID: {message_id4}")

    # Try to decrypt with ex-member (should fail)
    try:
        pre.decrypt_group_message("sasi@example.com", message_id4)
    except InvalidTag:
        print("Correctly prevented ex-member from decrypting")

    # Remaining members decrypt the fourth message
    for member in pre.groups["project_team"]["members"]:
        decrypted = pre.decrypt_group_message(member, message_id4)
        print(f"{member} decrypted fourth group message: {decrypted.decode()}")
