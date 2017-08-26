INCLUDE = include
BUILD = build
SRC = src

CC = gcc
CFLAGS = -I$(INCLUDE)

_DEPS = set1.h
DEPS = $(patsubst %,$(INCLUDE)/%,$(_DEPS))

_OBJ = set1.o cryptopals.o
OBJ = $(patsubst %,$(BUILD)/%,$(_OBJ))

$(BUILD)/%.o: $(SRC)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

cryptopals: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(BUILD)/*.o
