#!/usr/bin/make -f

.PHONY: all clean

all:
	$(MAKE) -C opensuse
	$(MAKE) -C fedora

clean:
	$(MAKE) -C opensuse clean
	$(MAKE) -C fedora clean
