MODULE=./pkcs11_module.so
OPENSC=/usr/lib/opensc-pkcs11.so
PKCSSPY=/usr/lib/pkcs11-spy.so
CMD="echo IT WORKS IT WORKS IT WORKS IT WORKS IT WORKS IT WORKS IT WORKS IT WORKS IT WORKS IT WORKS IT WORKS IT WORKS" 

HOST=127.0.0.1

AS	 = gcc
CC	 = gcc
LD	 = gcc
NM	 = nm
SIZE	 = size
OBJCOPY	 = objcopy
OBJDUMP	 = objdump

CCFLAGS  = -O2 -std=gnu99 -Wall -fPIC #-DDEBUG
LDFLAGS  = -lcrypto `curl-config --libs` -lm

OBJS = pkcs11.o cJSON.o https.o common.o

$(MODULE): $(OBJS)
	$(LD) -shared -Wl,-install_name,$(MODULE) -o $(MODULE) $(OBJS) $(LDFLAGS) 

%.o: %.c
	$(CC) -c $(CCFLAGS) $< -o $@

test: $(MODULE)
	ssh -I $(MODULE) $(HOST)

spyt: $(MODULE)
	PKCS11SPY=$(MODULE) ssh -I $(PKCSSPY) $(HOST) $(CMD)

spyo:
	PKCS11SPY=$(OPENSC) ssh -I $(PKCSSPY) $(HOST) $(CMD)

clean:
	rm -f *.o *.so
