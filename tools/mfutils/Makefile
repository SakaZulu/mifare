include $(ROOTDIR)/*.mk

CFLAGS += -I$(ROOTDIR)/devices
LDFLAGS += -lexpat

mfutils: mfutils.o mifare.o acr120s.o mf1rw.o utils.o
