import random

NUM_FALSE = 20
FLAG = "br4nch0u7"


def main(num_false):
    with open('dataset.csv', 'w') as file:
        seen = set()
        for i, c in enumerate(FLAG):
            bitstring = format(ord(c), '08b')
            seen.add(c)
            # i+1th label to signify position in string
            bitstring = list(bitstring)
            bitstring.append(str(i+1))
            file.write(','.join(bitstring) + '\n')

        # for every other character, label 0
        for _ in range(num_false):
            c = random.randint(33, 127)
            if chr(c) not in seen:
                bitstring = format(c, '08b')
                bitstring = list(bitstring)
                bitstring.append('0')
                file.write(','.join(bitstring) + '\n')


if __name__ == "__main__":
    main(NUM_FALSE)
