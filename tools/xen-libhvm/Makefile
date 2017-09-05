XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y :=
SUBDIRS-y += libhvm

clean:
	rm -rf *.a *.so *.o *.rpm $(LIB) *~ $(DEPS) TAGS

.PHONY: all clean install
all clean install: %: subdirs-%
