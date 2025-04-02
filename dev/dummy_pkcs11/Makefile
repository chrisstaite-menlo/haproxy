include ../../include/make/verbose.mk

CC       = gcc
OPTIMIZE = -O2 -g -fPIC
DEFINE   = -DUSE_OPENSSL=1 -DUSE_SSL=1
INCLUDE  = -I../../include
OBJS     = dummy_pkcs11.so

SSL_CFLAGS    := $(if $(SSL_INC),-I$(SSL_INC))
SSL_LDFLAGS   := $(if $(SSL_LIB),-L$(SSL_LIB)) -lssl -lcrypto

ifneq ($(USE_OPENSSL_AWSLC:0=),)
	DEFINE += -DUSE_OPENSSL_AWSLC=1
endif

dummy_pkcs11.so: dummy.c
	$(cmd_CC) -shared $(OPTIMIZE) $(DEFINE) $(INCLUDE) $(SSL_CFLAGS) $(SSL_LDFLAGS) $(ADDLIB) -o $@ $^

clean:
	rm -f $(OBJS) *.[oas] *~
