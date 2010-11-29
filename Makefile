BUILDDIR = build

DIRS = devices \
       tools/fetcher \
       tools/mfutils

all: $(BUILDDIR)
	@for i in $(DIRS); do \
		make -C $(BUILDDIR) -f $(CURDIR)/$$i/Makefile \
		ROOTDIR=$(CURDIR) SRCDIR=$(CURDIR)/$$i \
		--no-print-directory; \
	done

clean:
	@rm -fr $(BUILDDIR)

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

.PHONY: all clean $(BUILDDIR)
