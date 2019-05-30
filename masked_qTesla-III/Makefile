CC=gcc
DEBUG=TRUE
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCHITECTURE=_AMD64_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    ARM_SETTING=-lrt
else ifeq "$(ARCH)" "ARM64"
    ARCHITECTURE=_ARM64_
    ARM_SETTING=-lrt
endif


ORDER=1
TESTS=1000
RUNS=100



AR=ar rcs
RANLIB=ranlib

CFLAGS = -std=gnu11 -O3 -D $(ARCHITECTURE) -D __LINUX__ -D MASKING_ORDER=$(ORDER) -D NRUNS=$(RUNS) -D NTESTS=$(TESTS) -fomit-frame-pointer 
WARNINGS = -Wall -Wextra -Wimplicit-function-declaration -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes -Wundef -Wno-deprecated-declarations
LDFLAGS=-lm -L/usr/lib/ -lssl -lcrypto 

ifeq "$(CC)" "gcc"
    CFLAGS+= -march=native
endif

DFLAG=
ifeq "$(DEBUG)" "TRUE"
    DFLAG=-DDEBUG
endif

OBJECTS_I = objs_I/sign.o objs_I/pack.o objs_I/sample.o objs_I/gauss.o objs_I/poly.o objs_I/consts.o objs/fips202.o objs/random.o objs_I/sign_gadgets.o objs_I/base_gadgets.o objs_I/utils.o
SOURCE_TEST = tests/cpucycles.c tests/test_qtesla.c 
SOURCE_KATS_GEN  = tests/rng.c tests/PQCgenKAT_sign.c
SOURCE_KATS_TEST = tests/rng.c tests/PQCtestKAT_sign.c

all: lib_I tests simple

objs_I/%.o: %.c params.h
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(DFLAG) $(WARNINGS) $< -o $@

objs/random.o: random/random.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) random/random.c -o objs/random.o

objs/fips202.o: sha3/fips202.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) sha3/fips202.c -o objs/fips202.o

lib_I: $(OBJECTS_I) 
	rm -rf lib_I
	mkdir lib_I
	$(AR) lib_I/libqtesla.a $^
	$(RANLIB) lib_I/libqtesla.a

tests: lib_I tests/test_qtesla.c 
	$(CC) $(CFLAGS) -L./lib_I -D _qTESLA_I_ $(SOURCE_TEST) $(DFLAG) -Wno-deprecated-declarations -lqtesla $(LDFLAGS) -o test_qtesla $(ARM_SETTING)

simple: lib_I 
	$(CC) $(CFLAGS) -L./lib_I -D _qTESLA_I_ tests/simple_sign.c $(DFLAG) -Wno-deprecated-declarations -lqtesla $(LDFLAGS) -o test_simple $(ARM_SETTING)

.PHONY: clean

clean:
	rm -rf objs* lib* test_qtesla-* PQCgenKAT_sign-* PQCtestKAT_sign-* PQCsignKAT_qTesla* test_simple
