# The pcap given contains an account of a connection to a minecraft server. This is clear since the destination port is 25565, which is the port that Minecraft operates on by default.
# The followings wikis give some more info on the protocol. Note that they are outdated, so figuring out the correct packet ids to use takes some analysis of the packets that you find.
# https://prismarinejs.github.io/minecraft-data/?d=protocol&v=1.21.3  (Some minor changes made to the protocol make this outdated, packets were shifted a bit)
# https://c4k3.github.io/wiki.vg/Protocol.html
# You can extract the DER formatted RSA public key from the PCAP, and use any tools of your liking to do so. You can use cyberchef to do so as an example.
# The uncompressed packets that are used in the client server handshake start with the length and packet id. Then the subsequent data for that packet type follows.
# The public key DER comes from the encryption request clientbound packet with ID 0x01. 
# The client encrypts the AES key that it and the server will use with the servers public key. The ciphertext is PKCS1 V1.5 encoded.
# We need to be able to decrypt the ciphertext in order to find the shared secret used for AES.
ct= bytes.fromhex("3a808897b18680725936db912df57d0eb91251a5af13a50234375e6741efc9ceb7d9c22faa985eb7c05b7ac9cf1325e9de481ce7d5fa03bba94d9901dcb79cf9c63131c8249fcc376bd86992b2074a43d7985db1ba9b7e4e302447a6b99258dbc58d234e2c65119f24dc7d841c5fd721dbd80d6340d7f9478423474a600af221")
N = 0xb9c88f92d41bd494a2bfae195d5c30b24652204d9d53c569c42d08fdf27f41cf6f4467cd55695e61f13d7c8c83c7667bbb7c815355b5be18c4db0cdb1f3ecc7bcf208ea742a392a2173f462552f83aaa5761ae014d5dcf7f7b35730bcb5c669ff6bf72a70258f69332befe5a5592229b36dcc212865740c89b6a4df6460e5cb7 
e = 65537

# We now want to factor N, knowing p = a||b and q = b||a. We know this since the server JAR has an alteration made to the way that it generates
# its public key. You could find this by diffing the manifest files which contain hashes of every class, and looking at the mappings to understand
# what function has been changed. Any minecraft decompiler like fabric's or decompilerMC would work (I prefer decompilerMC since it puts the
# mappings in a directory that you can view yourself and it's more straight forward).
# Doing math we get that N = (ab)*(2^512+1)+(a^2+b^2)*2^256
# Most importantly, the high bits of ab are given by the higbits of N, where a bit error could happen depending on if a^2+b^2>2^512
# The low bits are just the low 256 bits of N
# We could also have an overflow of 2.
ablo = N%(2**256)
abhi = N>>(256*3)
ab3 = ((abhi-2)<<256)+ablo
ab2 = ((abhi-1)<<256)+ablo
ab1 = ((abhi)<<256)+ablo
asbs3 = ((N-(ab3)*((2**512)+1))>>256)
asbs2 = ((N-(ab2)*((2**512)+1))>>256)
asbs1 = ((N-(ab1)*((2**512)+1))>>256)

# We now compute (a+b)^2 and (a-b)^2 and check if they are squares.
from gmpy2 import iroot
check1, check2 = False, False
if asbs1-2*ab1>0:
    apb, check1 = iroot(asbs1+2*ab1, 2)
    amb, check2 = iroot(asbs1-2*ab1, 2)
if (not check1 or not check2) and asbs2-2*ab2>0:
    apb, check1 = iroot(asbs2+2*ab2, 2)
    amb, check2 = iroot(asbs2-2*ab2, 2)
if not check1 or not check2:
    apb, check1 = iroot(asbs3+2*ab3, 2)
    amb, check2 = iroot(asbs3-2*ab3, 2)
assert check1 and check2, "Something wrong happened"
assert apb%2==amb%2, "parity???"
a= (apb+amb)//2
b = (apb-amb)//2
p = a*2**256+b
assert N%p==0, "bad p or smth"
q = N//p
p, q = int(p), int(q)
print("Factored N!")

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

aeskey = PKCS1_v1_5.new(RSA.construct((N, e, pow(e, -1, (p-1)*(q-1)), p, q))).decrypt(ct, None)
print(aeskey)

from Crypto.Cipher import AES

aesClientBound = AES.new(aeskey, AES.MODE_CFB, iv=aeskey)
aesServerBound = AES.new(aeskey, AES.MODE_CFB, iv=aeskey)

# These files are extracted from wireshark. You can do this by using a display filter like "tcp.dstport eq 25565" and its negation to export the clientbound and serverbound
# packets to separate files. You can then follow the tcp stream on each one and "save as" the data (making sure you have the format set to raw). This is a basic way of doing 
# this and there are many other ways such as using tshark commands and what not.
# It is necessary to have two aes decryptions because clientbound and serverbound packets are encrypted independently
clientBoundStream = open("clientbound.txt", "rb").read()
serverBoundStream = open("serverbound.txt", "rb").read()

# Packet lengths are encoded using VarInts, which are bytes where 7 bits of it pertain to the integer, and the MSB indicates when to stop reading.
def readVarInt(s):
    field = []
    i = 0
    while i<len(s):
        field.append(s[i])
        if not s[i]&128:
            break
        i+=1
    n = 0
    for c in field[::-1]:
        n<<=7
        n+=c&0x7f
    return n, len(field)

n, c = readVarInt(serverBoundStream)
handshakePacket = serverBoundStream[:n+c]
serverBoundStream = serverBoundStream[n+c:]

n, c = readVarInt(serverBoundStream)
loginStartPacket = serverBoundStream[:n+c]
serverBoundStream = serverBoundStream[n+c:]

n, c = readVarInt(clientBoundStream)
encryptionRequestPacket = clientBoundStream[:n+c]
clientBoundStream = clientBoundStream[n+c:]

n, c = readVarInt(serverBoundStream)
encryptionResponsePacket = serverBoundStream[:n+c]
serverBoundStream = serverBoundStream[n+c:]


serverBoundStream = aesServerBound.decrypt(serverBoundStream)
clientBoundStream = aesClientBound.decrypt(clientBoundStream)

serverBoundPackets = []
clientBoundPackets = []
import zlib
while serverBoundStream:
    n, c = readVarInt(serverBoundStream)
    serverBoundPackets.append(serverBoundStream[:n+c])
    serverBoundStream = serverBoundStream[n+c:]
while clientBoundStream:
    n, c = readVarInt(clientBoundStream)
    clientBoundPackets.append(clientBoundStream[:n+c])
    clientBoundStream = clientBoundStream[n+c:]

# Now you can extract the interesting packets. Just printing them out for the writeup so you can see what's going on.
for p in serverBoundPackets:
    n, c = readVarInt(p)
    p = p[c:]
    if p[0]!=0:
        n, c = readVarInt(p)
        p = zlib.decompress(p[c:])
    else:
        p = p[1:]
    if p[0]==0x33 or p[0]==0x3c or p[0] == 0x7:
        print(p)
        
# You'll notice there's a consistent switching between first and second slot. You can find the inventory packet to figure out which is which.
# The block used to build the flag is in the second slot (coded as 0x01). You can confirm this by looking for inventory related packets and finding
# the "new" block (it was pale oak planks).
# Furthermore, the block locations given in the 0x33 packets are the location of the block that the new block was placed against.
# The packet contains a byte after the location (which is 8 bytes long), and takes on value 0, 1, 2, 3, 4, or 5.
# 0 indicates placing below a block (so we should subtract the y coordinate)
# 1 on top
# 2 subtract in z
# 3 increment z
# 4 decrement x
# 5 increment x

from Crypto.Util.number import *

def decodeLocation(val):
    x = val>>38
    y = (val)&0xfff
    z = (val>>12)&0x3FFFFFF
    if x>=2**25:
        x-=2**26
    if y>=2**11:
        y-=2**12
    if z>=2**25:
        z-=2**26
    return x, y, z

current = False
for p in serverBoundPackets:
    n, c = readVarInt(p)
    p = p[c:]
    if p[0]!=0:
        n, c = readVarInt(p)
        p = zlib.decompress(p[c:])
    else:
        p = p[1:]
    if p[0]==0x33:
        if p[2]==1:
            current = True
        else:
            current = False
    elif p[0]==0x3c and current:
        x, y, z = decodeLocation(bytes_to_long(p[2:10]))
        direction = p[10]
        if direction==0:
            y-=1
        elif direction==1:
            y+=1
        elif direction==2:
            z-=1
        elif direction==3:
            z+=1
        elif direction==4:
            x-=1
        elif direction==5:
            x+=1
        print(z, x, y, sep=', ')

#You can now put this into something like desmos 3D to read the flag.
