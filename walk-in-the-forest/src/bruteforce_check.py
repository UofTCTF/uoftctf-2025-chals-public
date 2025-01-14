import pickle
with open('model.pkl', 'rb') as f:
    clf = pickle.load(f)

# test values from 0 to 255 in binary
X = []
for i in range(256):
    bitstring = format(i, '08b')
    bitstring = list(bitstring)
    X.append(bitstring)

# predict labels using the model
y = clf.predict(X)


def get_rows_for_label(label):
    rows = []
    for i in range(len(y)):
        if y[i] == label:
            rows.append(X[i])
    return rows


for i in range(1, 10):
    print(f'\n\nLabel {i}:')
    for row in get_rows_for_label(i):
        print(chr(int(''.join(row), 2)), end='')
