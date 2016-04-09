#!/usr/bin/make -f

.PHONY: all clean

all:
	$(MAKE) -C fedora
	$(MAKE) -C opensuse
	$(MAKE) -C ubuntu
	$(MAKE) -C windows

clean:
	$(MAKE) -C fedora clean
	$(MAKE) -C opensuse clean
	$(MAKE) -C ubuntu clean
	$(MAKE) -C windows clean
