# Makefile

MARCH = native
#MARCH = mips32r2
#CROSS_COMPILE = mips-openwrt-linux-uclibc-

TARGET  = relay
BINDIR  = bin
OBJDIR  = obj
SRCDIR  = src

OBJECTS = main.o relay.o tun.o client.o util.o

COMMON = -g -Wall -march=$(MARCH) -O0 -flto -I$(SRCDIR)
CFLAGS  = $(COMMON) -std=gnu99
LDFLAGS = $(COMMON) -lcrypt -Wl,-O1,--sort-common,--as-needed,-z,relro

# ============================================================================ #

OBJLIST = $(addprefix $(OBJDIR)/, $(OBJECTS))

all: $(BINDIR)/$(TARGET) $(BINDIR)/$(TARGET).lss

clean:
	rm -rf $(OBJDIR) $(BINDIR)

$(BINDIR)/$(TARGET).lss: $(BINDIR)/$(TARGET)
	$(CROSS_COMPILE)objdump -h -S -C $< > $@

$(BINDIR)/$(TARGET): $(OBJLIST)
	mkdir -p $(dir $@)
	$(CROSS_COMPILE)gcc $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(dir $@)
	$(CROSS_COMPILE)gcc $(CFLAGS) -c -o $@ $<

# ============================================================================ #

format:
	./format.sh

.PHONY: all clean format
