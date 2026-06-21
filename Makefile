VICTIMSRCS = $(wildcard demos/victim*.c)
VICTIMBINS = $(addprefix demos/bin/, $(notdir $(VICTIMSRCS:.c=)))

CC?=musl-gcc
# Enable by default
CFLAGS+= -DSYMMAP_SUPPORT -DCONFIG_CACHE

ifeq ($(CC), musl-gcc)
	# Weird Arch Linux musl quirk
	CFLAGS += -fno-link-libatomic
endif

CFLAGS += -fdebug-prefix-map=$(CURDIR)=.

all: simulator demos

# Build simulator
simulator: simulator.c
	$(CC) $(CFLAGS) simulator.c -o simulator

# Build demos
demos: $(VICTIMBINS)

demos/bin/%: demos/%.c
	$(CC) $(CFLAGS) -I./ -g -static -o $@ $<

# Generate symmap files for demos
symmap: $(VICTIMBINS)
	for p in $(VICTIMBINS); do ./mksymmap.sh $$p; done

clean:
	rm -f simulator $(VICTIMBINS) $(VICTIMBINS:=.symmap)
