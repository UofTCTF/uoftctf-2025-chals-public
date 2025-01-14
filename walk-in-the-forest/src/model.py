import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)


def main(seed):
    data = pd.read_csv('dataset.csv', header=None)
    X = data.iloc[:, :-1]
    y = data.iloc[:, -1]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.05, random_state=seed)

    # train a random forest classifier
    clf = RandomForestClassifier(bootstrap=False)

    clf.fit(X_train, y_train)

    print("Test Accuracy: ", clf.score(X_test, y_test))

    with open('model.pkl', 'wb') as f:
        pickle.dump(clf, f)

    return X_train, X_test, y_train, y_test


if __name__ == "__main__":
    main(0)
