include $(ROOTDIR)/*.mk

CFLAGS += -I$(ROOTDIR)/libs -I$(ROOTDIR)/devices
LDFLAGS += -lexpat

mfutils: mfutils.o mifare.o acr120s.o mf1rw.o utils.o id.o aes256.o
