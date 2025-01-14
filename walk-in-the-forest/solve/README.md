https://arxiv.org/html/2402.19232v1

We can determine the model type by just inspecting the pickle.

The idea of the attack is to distill the decision trees into a set of constraints on the dataset based on the cardinality of each node in the decision tree. These constraints allow us to reconstruct the dataset with a high degree of accuracy due to the number of trees in the forest. The DRAFT attack simply extracts these constraints and sends them to any constraint solver; We then examine the dataset and notice the labels mark the positions of the flag, which are stored as characters in the samples.

Note that I attempted to make bruteforcing all possible inputs impossible by reducing the accuracy of the model, thus flooding the output with nonsense characters. However, since DRAFT chooses the dataset with maximum likelihood in the feasible space, we are still able to recover the original dataset (how cool!).

DRAFT attack is available on github at https://github.com/vidalt/DRAFT.