INCLUDE = include
BUILD = build
SRC = src

CC = gcc
CFLAGS = -g -I$(INCLUDE) -Wall

_DEPS = byte_string.h set1.h utils.h
DEPS = $(patsubst %,$(INCLUDE)/%,$(_DEPS))

_OBJ = byte_string.o set1.o utils.o cryptopals.o
OBJ = $(patsubst %,$(BUILD)/%,$(_OBJ))

$(BUILD)/%.o: $(SRC)/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD)/cryptopals: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean

clean:
	rm -rf $(BUILD)/*
