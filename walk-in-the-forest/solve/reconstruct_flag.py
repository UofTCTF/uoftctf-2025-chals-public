import pickle
import pandas as pd
from DRAFT.DRAFT import DRAFT
from DRAFT.utils import *
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)


def main(seed, X_train=None):
    with open('model.pkl', 'rb') as f:
        clf = pickle.load(f)

    # print(f"Number of trees (n_estimators): {clf.n_estimators}")
    # print(
    #     f"Max depth of trees (max_depth): {max([estimator.tree_.max_depth for estimator in clf.estimators_])}")
    # print("Accuracy on test set: ", clf.score(X_test, y_test))

    # plot example tree
    # sklearn.tree.plot_tree(clf.estimators_[0], filled=True, fontsize=8)
    # plt.show()

    extractor = DRAFT(clf)
    dict_res = extractor.fit(bagging=False, method="cp-sat",
                             timeout=60, verbosity=False, n_jobs=-1, seed=seed)

    # Retrieve solving time and reconstructed data
    duration = dict_res['duration']
    x_sol = dict_res['reconstructed_data']

    # Evaluate and display the reconstruction rate
    if X_train is not None:
        # for experiment.py
        e_mean, list_matching = average_error(x_sol, X_train.to_numpy())

    print("Complete solving duration :", duration)
    # print("Reconstruction Error: ", e_mean)

    x_sol = pd.DataFrame(x_sol)
    y = clf.predict(x_sol)
    x_sol['label'] = y

    # Reconstruct the flag
    flag_length = 9
    flag = ['_'] * flag_length

    for i in range(flag_length):
        # Label i+1 corresponds to position i in the flag
        row = x_sol[x_sol[x_sol.columns[-1]] == i + 1]
        if not row.empty:
            bitstring = ''.join(row.iloc[0, :-1].astype(str))
            flag[i] = chr(int(bitstring, 2))
    print(''.join(flag))

    if X_train is not None:
        return e_mean


if __name__ == "__main__":
    main(0)
