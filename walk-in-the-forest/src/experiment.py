import reconstruct_flag
import model
import create_dataset
import numpy as np

if __name__ == "__main__":
    # Experiment to check bruteforceability of the flag across 10 seeds
    # while preserving reconstruction error
    errors = []
    for seed in range(10):
        create_dataset.main(20)  # 20 false entries
        X_train, _, __, ___ = model.main(seed)
        errors.append(reconstruct_flag.main(seed, X_train))
    print("Errors: ", errors)
    print("Average error: ", np.mean(errors))
