import itertools
import tqdm
import aes

def divide_chunks(l, n):
    for i in range(0, len(l), n): 
        yield l[i:i + n]

f = open("flag.enc", "rb")
sbox = list(f.read(256))
aes.s_box = sbox
aes.inv_s_box = [0]*256
for i in range(256):
    aes.inv_s_box[i] = aes.s_box.index(i)
curr_sbox = [-1]*256
randStates = []

def checkPossible(n, rand):
    idx = sbox.index(n)
    while rand != idx:
        if sbox[rand] > n:
            return False
        rand = (rand + 1)%256
    return True

def checkFull(n, rand):
    return (n>>24) < 128 and checkPossible(n*4, rand&0xff) and checkPossible(n*4 + 1, (rand>>8)&0xff) and checkPossible(n*4 + 2, (rand>>16)&0xff) and checkPossible(n*4 + 3, (rand>>24)&0xff)


for i in range(31 * 4):
    pos = []
    idx = sbox.index(i)
    curr_sbox[idx] = i
    while curr_sbox[idx] != -1:
        pos.append(idx)
        idx = (idx - 1) % 256
    randStates.append(pos)


randStates = [list(map(lambda x: int.from_bytes(bytes(x), 'little'), itertools.product(*i))) for i in divide_chunks(randStates, 4)]
print([len(i) for i in randStates])
print([[hex(j) for j in i] for i in randStates])
for i in range(31, 64):
    newState = set()
    for a, b in itertools.product(randStates[-31], randStates[-3]):
        newState.add((a + b)%(2**31))
        newState.add((a + b + 1)%(2**31))
    newState = list(filter(lambda x: checkFull(i, x), newState))
    print(i, len(newState))
    randStates.append(newState)


for i in range(64, 66):
    newState = set()
    for a, b in itertools.product(randStates[-31], randStates[-3]):
        newState.add((a + b)%(2**31))
        newState.add((a + b + 1)%(2**31))
    newState = list(filter(lambda x: (x>>24) < 128, newState))
    randStates.append(list(newState))

print(list(map(len, randStates)))

possible_keys = randStates[-2:]

enc = list(divide_chunks(f.read(), 16))
print(list(map(len, possible_keys)))
print(len(possible_keys[0])*len(possible_keys[1]))
for a, b in tqdm.tqdm(itertools.product(*possible_keys), total=len(possible_keys[0])*len(possible_keys[1])):
    key = a.to_bytes(8, 'little') + b.to_bytes(8, 'little')
    ciph = aes.AES(key)
    dec = ciph.decrypt_block(enc[0])
    if dec.startswith(b'uoftctf'):
        print(b''.join([ciph.decrypt_block(i) for i in enc]))
        exit()