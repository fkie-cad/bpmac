CONTIKI=..
CONTIKI_PROJECT = client
TESTS = test
TINYDTLS_PATH := os/net/security/tinydtls

MAKE_WITH_DTLS ?= 1

ifeq (${wildcard $(CONTIKI)/$(TINYDTLS_PATH)/Makefile},)
${error Could not find the tinyDTLS submodule. Please run "git submodule update --init" and try again}
endif

CFLAGS += -DWITH_DTLS=1 -DMAC_LEN=16 -DIS_ZOUL=1 -DUSE_HW_ACCEL=1

MODULES += bpmac/tinydtls-support
MODULES += $(TINYDTLS_PATH) ${addprefix $(TINYDTLS_PATH)/,aes sha2 ecc}

PROJECT_SOURCEFILES += hmac.c bpmac.c umac.c

include $(CONTIKI)/Makefile.include

all: $(CONTIKI_PROJECT)

test: $(TESTS)
