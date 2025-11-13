CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
TARGET ?= packet_generator

all: $(TARGET)

$(TARGET): packet_generator.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
