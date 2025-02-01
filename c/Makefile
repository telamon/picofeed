CC=clang
CFLAGS=-Wall -g $(shell pkg-config --cflags monocypher)
LDFLAGS=$(shell pkg-config --libs monocypher)

TARGET_LIB=picofeed.so

TARGET=test_pico
SOURCES=test/picofeed_test.c picofeed.c test/log.c

all: $(TARGET) $(TARGET_LIB)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_LIB)

test: clean $(TARGET)
	./$(TARGET)

debug: clean $(TARGET)
	lldb -o 'settings set interpreter.prompt-on-quit false' -o 'run' $(TARGET)

lib: $(TARGET_LIB)

$(TARGET_LIB): picofeed.c
	$(CC) $(CFLAGS) -shared -Oz -o $(TARGET_LIB) $^ $(LDFLAGS)

cloc:
	cloc picofeed.c picofeed.h
