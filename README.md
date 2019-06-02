# Masked_qTESLA

Masked implementation of the [qTESLA post-quantum signature scheme](https://qtesla.org/).

See https://eprint.iacr.org/2019/606 for more details about the masking scheme. 

Tests are run automatically for multiple masking order by the run_tests.py script. Results are written in /tests/benchmarks.
The cortex-M4 version has been implemented using the code of the [pqm4](https://github.com/mupq/pqm4) library to communicate with the chip.
