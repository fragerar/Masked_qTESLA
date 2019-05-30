OPENCM3DIR  = libopencm3
OPENCM3NAME = opencm3_stm32f4
OPENCM3FILE = $(OPENCM3DIR)/lib/lib$(OPENCM3NAME).a
LDSCRIPT    = $(OPENCM3DIR)/lib/stm32/f4/stm32f405x6.ld

PREFIX     ?= arm-none-eabi
CC          = $(PREFIX)-gcc
LD          = $(PREFIX)-gcc
OBJCOPY     = $(PREFIX)-objcopy
OBJDUMP     = $(PREFIX)-objdump
GDB         = $(PREFIX)-gdb

ARCH_FLAGS  = -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16
DEFINES     = -DSTM32F4

CFLAGS     += -O3 \
			  -std=gnu99 \
              -I$(OPENCM3DIR)/include \
              -fno-common $(ARCH_FLAGS) -MD $(DEFINES)
LDFLAGS    += --static -Wl,--start-group -lc -lgcc -lnosys -Wl,--end-group \
              -T$(LDSCRIPT) -nostartfiles -Wl,--gc-sections \
               $(ARCH_FLAGS) -L$(OPENCM3DIR)/lib




#              -Wall -Wextra -Wimplicit-function-declaration \
#              -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes \
#              -Wundef -Wshadow \

COMMONPATH=common

HEADERS = $(COMMONPATH)/fips202.h $(COMMONPATH)/random.h
SOURCES= $(COMMONPATH)/stm32f4_wrapper.c $(COMMONPATH)/fips202.c $(COMMONPATH)/random.c
OBJECTS = stm32f4_wrapper.o fips202.o random.o
MASKED_QTESLA_OBJECTS = sign.o pack.o sample.o gauss.o poly.o consts.o sign_gadgets.o base_gadgets.o utils.o


all: main.bin

main.elf: main.c $(SOURCES) $(OBJECTS) $(MASKED_QTESLA_OBJECTS) $(LDSCRIPT)
	$(CC) -o $@ $< $(OBJECTS) $(MASKED_QTESLA_OBJECTS) -I$(COMMONPATH) $(CFLAGS) $(LDFLAGS) -l$(OPENCM3NAME) 
	

%.bin: %.elf
	$(OBJCOPY) -Obinary $(*).elf $(*).bin

%.o: %.c $(HEADERS)
	$(CC) -I$(COMMONPATH) $(CFLAGS) -c -o $@ $<

%.o: %.S $(HEADERS)
	$(CC) -I$(COMMONPATH) $(CFLAGS) -c -o $@ $<


stm32f4_wrapper.o:  $(COMMONPATH)/stm32f4_wrapper.c
	$(CC) $(CFLAGS) -o $@ -c $^

fips202.o:  $(COMMONPATH)/fips202.c
	$(CC) $(CFLAGS) -o $@ -c $^

random.o:  $(COMMONPATH)/random.c
	$(CC) $(CFLAGS) -o $@ -c $^



.PHONY: clean

flash:
	st-flash --reset write main.bin 0x8000000

clean:
	-rm -f *.d
	-rm -f *.s
	-rm -f *.o
	-rm -f *.bin
	-rm -f *.elf
