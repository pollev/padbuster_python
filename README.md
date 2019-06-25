# padbuster_python
A python implementation of a padding oracle attack

Usage:
```
./padding_oracle.py [encrypt|decrypt]
```

You must also edit the script and update all values in the section marked 'FILL IN'.
```
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
```

This tool also assumes that the server is using a cookie to store the CBC token in a base64 encoded format. If this is not the case, you might need to tinker with the functions 'encrypt', 'decrypt' and 'test_token' to supply the data in your desired format
