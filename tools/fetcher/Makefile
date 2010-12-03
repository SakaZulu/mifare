include $(ROOTDIR)/*.mk

CFLAGS += -I$(ROOTDIR)/libs -I$(ROOTDIR)/devices
LDFLAGS += -lexpat

fetcher: fetcher.o mifare.o acr120s.o mf1rw.o utils.o
