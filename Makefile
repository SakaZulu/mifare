BUILDDIR := build

ifeq (,$(SRCDIR))

################################
# Parent, run in root directory
################################

.SUFFIXES:

ARCH := $(shell uname -m)
ARCHDIR := $(BUILDDIR)/$(ARCH)

MAKETARGET = $(MAKE) --no-print-directory -C $@ -f $(CURDIR)/Makefile \
						 SRCDIR=$(CURDIR) ARCH=$(ARCH) $(MAKECMDGOALS)

.PHONY: $(ARCHDIR)
$(ARCHDIR):
	+@[ -d $@ ] || mkdir -p $@
	+@$(MAKETARGET)

Makefile : ;

% :: $(ARCHDIR) ; :

.PHONY: clean
clean:
	+@rm -rf $(BUILDDIR)

else

################################
# Child, run in build directory
################################

VPATH = $(SRCDIR)

%.o: %.c
	$(COMPILE.c) -Wp,-MD,$*.d -o $@ $<
	@cp $*.d $*.P; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
		-e '/^$$/ d' -e 's/$$/ :/' < $*.d >> $*.P; \
		rm -f $*.d

CFLAGS = -Wall -O2

APPS = fetcher tester select read write

.PHONY: all
all: $(APPS)

fetcher: fetcher.o acr120.o
tester: tester.o acr120.o
select: select.o acr120.o
read: read.o acr120.o
write: write.o acr120.o

-include *.P

endif
