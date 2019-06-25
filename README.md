# padbuster_python
A python implementation of a padding oracle attack

Usage:
    ./padding_oracle.py [encrypt|decrypt]

You must also edit the script and update all values in the section marked 'FILL IN'.
This tool also assumes that the server is using a cookie to store the CBC token in a base64 encoded format
If this is not the case, you might need to tinker with the functions 'encrypt', 'decrypt' and 'test_token' to supply the data in your desired format
