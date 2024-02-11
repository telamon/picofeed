CC=clang
CFLAGS=-Wall -g $(shell pkg-config --cflags monocypher)
LDFLAGS=$(shell pkg-config --libs monocypher)

TARGET=picofeed_test
SOURCES=test/picofeed_test.c picofeed.c test/log.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

debug: clean $(TARGET)
	lldb -o 'settings set interpreter.prompt-on-quit false' -o 'run' $(TARGET)

cloc:
	cloc picofeed.c picofeed.h
