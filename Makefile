#!/usr/bin/make -f

.PHONY: all clean

all:
	$(MAKE) -C opensuse

clean:
	$(MAKE) -C opensuse clean
