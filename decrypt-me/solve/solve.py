from pyads import ADS
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from time import time
import random
import datetime
# crack rar with rockyou.txt to discover password is toronto416
KEY = SHA256.new(str(random.getrandbits(256)).encode()).digest()
file = "flag.py"
handler = ADS(file)
if handler.has_streams():
    for stream in handler:
        print(f"Stream: {stream}")
        
encrypted = handler.get_stream_content("flag.enc")

# try seeding random with all times from  2025:01:05 21:13:00-05:00 to 2025:01:05 21:13:59-05:00
start_time = datetime.datetime(2025, 1, 5, 21, 13, 0)

for i in range(60):
    random.seed(int((start_time + datetime.timedelta(seconds=i)).timestamp()))
    key = SHA256.new(str(random.getrandbits(256)).encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX, nonce=encrypted[:16])
    try:
        decrypted = cipher.decrypt(encrypted[16:])
        print(f"Decrypted flag: {decrypted.decode()}")
    except:
        pass
