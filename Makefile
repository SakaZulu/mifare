CFLAGS = -Wall -O2

SRCS = acr120.c tester.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(OBJS)

clean:
	rm -f $(OBJS)

# Auto Dependencies: http://make.paulandlesley.org/autodep.html
DEPDIR = .deps
df = $(DEPDIR)/$(*F)

%.o : %.c
	@mkdir -p $(DEPDIR)
	$(COMPILE.c) -Wp,-MD,$(df).d -o $@ $<
	@cp $(df).d $(df).P; \
		sed -e 's/#.*//' -e 's/^[^:]*: *//' -e 's/ *\\$$//' \
		    -e '/^$$/ d' -e 's/$$/ :/' < $(df).d >> $(df).P; \
		rm -f $(df).d

-include $(SRCS:%.c=$(DEPDIR)/%.P)
