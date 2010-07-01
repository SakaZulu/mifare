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

APPS = fetcher
OBJS = mifare.o acr120s.o mf1rw.o utils.o

CFLAGS = -Wall -O2

.PHONY: all
all: $(APPS)

fetcher: fetcher.o $(OBJS)
#tester: tester.o $(OBJS)
#select: select.o $(OBJS)
#read: read.o $(OBJS)
#write: write.o $(OBJS)

-include *.P

endif
