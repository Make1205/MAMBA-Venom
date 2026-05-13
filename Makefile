# Root build entry point for MAMBA-Frost.
.PHONY: all clean check size_test

all:
	$(MAKE) -C Frost all

clean:
	$(MAKE) -C Frost clean

check:
	$(MAKE) -C Frost check

size_test:
	$(MAKE) -C Frost size_test
