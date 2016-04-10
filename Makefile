#!/usr/bin/make -f

.PHONY: all clean

all:
	$(MAKE) -C check-style
	$(MAKE) -C fedora
	$(MAKE) -C opensuse
	$(MAKE) -C scan-build
	$(MAKE) -C ubuntu
	$(MAKE) -C windows

clean:
	$(MAKE) -C check-style clean
	$(MAKE) -C fedora clean
	$(MAKE) -C opensuse clean
	$(MAKE) -C scan-build clean
	$(MAKE) -C ubuntu clean
	$(MAKE) -C windows clean
