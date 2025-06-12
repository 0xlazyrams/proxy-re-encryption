from umbral import SecretKey, Signer
from umbral import encrypt, decrypt_original
from umbral import reencrypt
from umbral import decrypt_reencrypted
from umbral import generate_kfrags
# import sys

plaintext = "This is Alice's message"
threshold=3
shares=5

# if (len(sys.argv)>1):
#   plaintext=str(sys.argv[1])
# if (len(sys.argv)>2):
#   threshold=int(sys.argv[2])
# if (len(sys.argv)>3):
#   shares=int(sys.argv[3])

plain=plaintext.encode()

alice_private_key = SecretKey.random()
alice_public_key = alice_private_key.public_key()
alice_signer = Signer(alice_private_key)

# Bob's keys
bob_private_key = SecretKey.random()
bob_public_key = bob_private_key.public_key()


# Use Alice's public key to encrypt
capsule, ciphertext = encrypt(alice_public_key, plain)

# Try Alice's private key to decrypt
cleartext = decrypt_original(alice_private_key, capsule, ciphertext)


# Split key into fragments for t out of n
kfrags = generate_kfrags(delegating_sk=alice_private_key,
                         receiving_pk=bob_public_key,
                         signer=alice_signer,
                         threshold=threshold,
                         shares=shares)

# Bob collects the fragments
cfrags = list()        
for kfrag in kfrags[:threshold]:
    cfrag = reencrypt(capsule=capsule, kfrag=kfrag)
    cfrags.append(cfrag)    


bob_cleartext = decrypt_reencrypted(receiving_sk=bob_private_key,
                                        delegating_pk=alice_public_key,
                                        capsule=capsule,
                                        verified_cfrags=cfrags,
                                        ciphertext=ciphertext)

print(f"Plaintext: {plaintext}")
print(f"Threshold: Any {threshold} from {shares}")

print(f"\nAlice's private key: {alice_private_key.to_secret_bytes().hex()}")
print(f"Alice's public key: {alice_public_key.point().to_affine()}")
print(f"\nBob's private key: {bob_private_key.to_secret_bytes().hex()}")
print(f"Bob's public key: {bob_public_key.point().to_affine()}")

print(f"\nAlice decrypted text: {cleartext.decode()}")
print(f"Bob decrypted text: {bob_cleartext.decode()}")