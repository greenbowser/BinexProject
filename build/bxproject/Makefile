
CC = gcc
# Hardening Flags:
# -Wl,-z,relro,-z,now: Full RELRO to make GOT read-only.
# -fstack-protector-all: Enable stack canaries for all functions.
# -O2: Standard optimizations.
# -no-pie: Disable PIE for simplicity, making the binary's addresses static.
#          You can remove this to make it a PIE binary for an extra step.
CFLAGS = -O0 -fstack-protector-all -g
LDFLAGS = -Wl,-z,relro,-z,now 

all: vuln

vuln: vuln.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f vuln