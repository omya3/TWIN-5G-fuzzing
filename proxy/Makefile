CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
LDLIBS ?= -lsctp

TARGET := sctp_ngap_proxy

.PHONY: all clean

all: $(TARGET)

$(TARGET): sctp_ngap_proxy.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(TARGET)
