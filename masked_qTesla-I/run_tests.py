from os import system, popen
import sys
PATH = "./tests/benchmarks"
open(PATH, 'w').close() # clear file
cur = ""
res = ""

VERBOSE_COMPILE = True
REDIRECT = ""
MAX_ORDER = 5
RUNS_SIGN = 10000
RUNS_GADGETS = 1000000


PARAM_MAKE = " RUNS="+str(RUNS_SIGN)+" TESTS="+str(RUNS_GADGETS)+" "
if sys.platform == 'darwin':
	PARAM_MAKE += "CC=clang "


if not VERBOSE_COMPILE:
	REDIRECT=">/dev/null"
with open(PATH,'a') as f:

	for i in range(1, MAX_ORDER+1):
		print("Compiling for masking of order", i)
		system("make clean > /dev/null && make ORDER="+str(i)+PARAM_MAKE+REDIRECT)
		print("Running tests...", end ='')
		sys.stdout.flush()
		cur = popen("./test_qtesla-I").read()
		print("Writing to "+PATH+" ...")
		f.write(cur)
		res += cur
		print(cur)
		print("Done.")

  
  

