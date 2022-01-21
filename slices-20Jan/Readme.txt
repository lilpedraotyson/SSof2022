These example slices are provided with the aim of helping to point out:

- possible ways in which programs can encode dependencies that you might be overlooking
- that the analysis that your tool should perform is independent of the actual names of functions and variables and what are their perceived meaning or usage in real JavaScript frameworks
- that the existence of a vulnerability or sanitization depends on whether and how function names appear in the vulnerability patterns, and in which positions

They contain types of flows that will be considered in the evaluation, some of which are corner cases for distinguishing the highest grades.

One input pattern and corresponding output example is provided for each slice.  Observe that other input patterns could reveal other aspects of the flows encoded in the slice.  These are not meant to be exaustive test-cases, and you are expected to consider other possibles that could be relevant for the approach that you are taking with your tool.
