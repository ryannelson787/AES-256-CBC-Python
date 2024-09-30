from aes256 import AES_256_CBC

from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
#key = b"abcdefghijklmnopqrstuvwxyzabcdef"

custom_iv = b'some_16_bytes_iv'

cipher = AES_256_CBC()

original_message = 'Write any message here. This text will be encrypted, then decrypted.'
byte_text = original_message.encode()

ciphertext = cipher.encrypt(byte_text, key, custom_iv)
plaintext = cipher.decrypt(ciphertext, key, custom_iv)

ciphertext_hex = ''.join(format(x, '02x') for x in ciphertext)

print("Encrypted Message (hex): ", ciphertext_hex)
print("Decrypted Message: ", plaintext.decode())