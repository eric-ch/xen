XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

HVM_INFO_SRC = main.c
HVM_INFO_OBJ = $(HVM_INFO_SRC:.c=.o)

CFLAGS += -Werror -Wall -I../libxc/include -I../include

all: hvm-info

.PHONY: clean
clean:
	rm -f $(HVM_INFO_OBJ)

.PHONY: TAGS
TAGS:
	etags `find . -name '*.[ch]'`

.PHONY: install
install: all
	$(INSTALL_PROG) hvm-info $(DESTDIR)$(BINDIR)

-include $(DEPS)

hvm-info: $(HVM_INFO_OBJ)
	$(CC) $(LDFLAGS) $^ -o $@ -lxenctrl -L../libxc

# never delete any intermediate files.
.SECONDARY:
