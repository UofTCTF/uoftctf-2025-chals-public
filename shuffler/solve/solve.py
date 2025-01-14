from fractions import Fraction
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

class HorseShoe:
    def __init__(self, initial_state):
        self.x = Fraction(initial_state[0])
        self.y = Fraction(initial_state[1])

    def next(self):
        num = self.x + self.y
        # Horseshoe map
        if self.y <= 1/2:
            self.x, self.y = self.x/2, 2*self.y
        elif self.y >= 1/2:
            self.x, self.y = 1 - self.x/2, 2 - 2*self.y
        return num

    def random_number(self, n=1):
        return int(self.next()*n/2)


class Arrangement:
    def __init__(self, seed, n):
        self.seed = seed
        self.nums = [i for i in range(1, n+1)]
        self.shuffle(n)

    def shuffle(self, n):
        new_nums = []
        for i in range(n):
            num_index = self.seed % (n - i)
            new_nums.append(self.nums.pop(num_index))
            self.seed //= (n - i)
        self.nums = new_nums


def reverse(seq):
    seed = 0
    mult = 1
    nums = [i for i in range(1, len(seq)+1)]
    for i in seq:
        for j, k in enumerate(nums):
            if i == k:
                seed += mult*j
                mult *= len(nums)
                nums.pop(j)
                break
    return seed

if __name__ == "__main__":
    flag = b'HorseShoeMapChal' #hide
    initial_y = '167952327246618/375299968947541' #hide
    initial_x = '335904654493236/375299968947541' #hide
    rng = HorseShoe((initial_y, initial_x))
    key = sha256(long_to_bytes(rng.random_number(2**100))).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    flag = cipher.encrypt(flag)
    print(f"Welcome to the shuffler! Here's the flag if you are here for it {flag.hex()}.")
    for i in range(49):
        bound = 30
        if bound < 1:
            print("Pick positive numbers!")
            continue
        if bound > 30:
            print("That's too much for me!")
            continue
        lst = Arrangement(rng.random_number(2**100), bound).nums
        seed = reverse(lst)
    key = sha256(long_to_bytes(seed)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    flag = cipher.decrypt(flag)
    print(flag)

