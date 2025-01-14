from pwn import *
import secrets

MASK = (1<<64)-1

def rotl(x, k):
    return ((x<<k)&MASK)|(x>>(64-k))

class PRNG():
    def __init__(self, state):
        self.p = 0
        assert not all(i==0 for i in state)
        assert len(state)==16
        assert all(i<(1<<64) for i in state)
        self.state = state
    def next(self):
        q = self.p
        self.p = (self.p+1)&15
        s0 = self.state[self.p]
        s15 = self.state[q]
        res = (rotl(s0+s15, 23)+s15)&MASK
        s15^=s0
        self.state[q] = (rotl(s0, 25)^s15^(s15<<27))&MASK
        self.state[self.p] = rotl(s15, 36)
        return int(11*res/(2**64))


r = remote("127.0.0.1", 5000) #Change to the correct IP

r.recvuntil(b'Salt: ')
salt = eval(r.readline().strip().decode())
print(salt)


# The internal state of the RNG (one of the Xoroshiro 1024 PRNGs) is an LFSR, it is linear.
# Namely, if f is the function that maps one state to the next, f(a^b) = f(a)^f(b)
# This means that if we know the difference between two RNG states, then we know the difference
# for all the states after that. Now given that the the final output depends mainly on the high
# bits of res, which in turn relies mostly on just a few bits in the state, we can find certain
# calls within the RNG with a certain salt. For example if the difference between two states is
# 0 in the bits which matter, most likely the outputs of both RNGs will match.
# Doing this analysis is a bit annoying to do, so instead we just simulate the correlation, and
# find the points in the state where there is a high correlation of at least 40%.
n = 50000 # How many calls to brute force through
iters = 200 # Number of seeds to try
cor = [{} for i in range(n)]
for z in range(iters):
    seed = [secrets.randbits(64) for i in range(16)]
    seed2 = [i^j for i,j in zip(seed, salt)]
    rng1 = PRNG(seed)
    rng2 = PRNG(seed2)
    for i in range(n):
        res1 = rng1.next()
        res2 = rng2.next()
        if res1 not in cor[i]:
            cor[i][res1] = {}
        if res2 not in cor[i][res1]:
            cor[i][res1][res2] = 0
        cor[i][res1][res2]+=1

# Now that we have constructed the correlations, we want to find the ones which are high.

def computeCorrelation(d):
    total = sum(d[i] for i in range(11) if i in d)
    mx  = 0
    mxInt = -1
    for i in range(11):
        if i not in d:
            continue
        if d[i]>mx:
            mx = d[i]
            mxInt = i
    return mx/total, mxInt
        


goodSteps = []
for i in range(n):
    if len(goodSteps)>=50:
        break
    mn = 2
    choices = []
    for j in range(11):
        if j not in cor[i]:
            break
        percent, best = computeCorrelation(cor[i][j])
        if percent<mn:
            mn = percent
        choices.append(best)
    else:
        if mn>=0.4:
            goodSteps.append((i, choices))
print(len(goodSteps))
if len(goodSteps)!=50:
    print("Sorry we got unlucky")

    #If this happens you might want to increase n but it should be fine
print(r.readline())
print(r.readline())
r.sendline(' '.join(list(map(lambda x: str(x[0]), goodSteps))).encode())
for i in range(50):
    res1 = int(r.readline().decode().strip())
    guess = goodSteps[i][1][res1]
    r.readline()
    r.sendline(str(guess).encode())
r.recvuntil(b'score of ')
score = int(r.readline().decode())
if score>=20:
    print(r.readline())
