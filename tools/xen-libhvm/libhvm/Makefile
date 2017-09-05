XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

LIBHVM_OBJS = xenhvm.o smbios_module.o acpi_module.o xh_internal.o

LIBHVM_PIC_OBJS = $(patsubst %.o,%.opic,$(LIBHVM_OBJS))
LIBHVM_LIBS = $(LDLIBS_libxenstore)
$(LIBHVM_OBJS) $(LIBHVM_PIC_OBJS): CFLAGS += $(CFLAGS_libxenstore)

MAJOR = 1.0
MINOR = 0

CFLAGS += -I.

.PHONY: all
all: libxenhvm.so libxenhvm.a

libxenhvm.so: libxenhvm.so.$(MAJOR)
	ln -sf $< $@

libxenhvm.so.$(MAJOR): libxenhvm.so.$(MAJOR).$(MINOR)
	ln -sf $< $@

libxenhvm.so.$(MAJOR).$(MINOR): $(LIBHVM_PIC_OBJS)
	$(CC) $(LDFLAGS) -Wl,$(SONAME_LDFLAG) -Wl,libxenhvm.so.$(MAJOR) $(SHLIB_LDFLAGS) -o $@ $^ $(LIBHVM_LIBS) $(APPEND_LDFLAGS)

libxenhvm.a: $(LIBHVM_OBJS)
	$(AR) rcs libxenhvm.a $^

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(LIBDIR)
	$(INSTALL_DIR) $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL_PROG) libxenhvm.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)
	ln -sf libxenhvm.so.$(MAJOR).$(MINOR) $(DESTDIR)$(LIBDIR)/libxenhvm.so.$(MAJOR)
	ln -sf libxenhvm.so.$(MAJOR) $(DESTDIR)$(LIBDIR)/libxenhvm.so
	$(INSTALL_DATA) libxenhvm.a $(DESTDIR)$(LIBDIR)
	$(INSTALL_DATA) xenhvm.h $(DESTDIR)$(INCLUDEDIR)

.PHONY: clean
clean:
	$(RM) -f *.o *.opic *.so* *.a $(DEPS)

distclean: clean

-include $(DEPS)
