OBJECTS = mem.o thread.o log.o fd.o dispatcher.o
TARGET = libm10k.so
INCLUDES = -Iinclude
CFLAGS += -fPIC -O3 $(INCLUDES)
LDFLAGS = -fPIC -shared -Wl,-soname,$(TARGET),-z,noexecstack,-z,noexecheap,-z,pic,-z,now \
          -L$(PREFIX)lib
LIBS = -lpthread

PHONY = clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -Wall -O3 $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -rf $(OBJECTS) $(TARGET)

.PHONY: $(PHONY)
