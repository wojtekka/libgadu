SUBDIRS = connect dcc7 protocol

all:
	for i in $(SUBDIRS); do make -C $$i; done

test:
	for i in $(SUBDIRS); do make -C $$i test; done

clean:
	for i in $(SUBDIRS); do make -C $$i clean; done

.PHONY:	all test clean
