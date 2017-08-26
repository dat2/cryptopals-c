INCLUDE = include
BUILD = build
SRC = src

CC = gcc
CFLAGS = -I$(INCLUDE) -Wall

_DEPS = set1.h
DEPS = $(patsubst %,$(INCLUDE)/%,$(_DEPS))

_OBJ = set1.o cryptopals.o
OBJ = $(patsubst %,$(BUILD)/%,$(_OBJ))

$(BUILD)/%.o: $(SRC)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(BUILD)/cryptopals: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(BUILD)/*.o
