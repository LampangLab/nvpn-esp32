# Host test build (gcc/clang). Builds libsecp256k1 straight from third_party.
CC ?= gcc
SECP = ../third_party/secp256k1
SECP_DEFS = -DECMULT_WINDOW_SIZE=4 -DECMULT_GEN_PREC_BITS=2 -DENABLE_MODULE_SCHNORRSIG -DENABLE_MODULE_EXTRAKEYS -DENABLE_MODULE_ECDH -DUSE_EXTERNAL_DEFAULT_CALLBACKS
CFLAGS = -std=c11 -O1 -g -Wall -Wextra -Wno-unused-parameter -I../include -I../src -I$(SECP)/include $(SANITIZE)
SRCS = ../src/nvpn_core.c ../src/nvpn_event.c ../src/nvpn_roster.c ../src/nvpn_dns.c ../src/nvpn_sha256.c $(FIPS_SRCS)

all: test
SECP_CC = $(CC) -c -O2 -w -DSECP256K1_BUILD $(SECP_DEFS) -I$(SECP) -I$(SECP)/src -I$(SECP)/include
secp256k1.o: $(SECP)/src/secp256k1.c
	$(SECP_CC) $< -o $@
pre_ecmult.o: $(SECP)/src/precomputed_ecmult.c
	$(SECP_CC) $< -o $@
pre_gen.o: $(SECP)/src/precomputed_ecmult_gen.c
	$(SECP_CC) $< -o $@
SECP_OBJS = secp256k1.o pre_ecmult.o pre_gen.o
test_nvpn: test_nvpn.c $(SRCS) $(SECP_OBJS) vectors.h
	$(CC) $(CFLAGS) test_nvpn.c $(SRCS) $(SECP_OBJS) -o $@
test: test_nvpn
	./test_nvpn
asan:
	$(MAKE) clean && $(MAKE) SANITIZE="-fsanitize=address,undefined -fno-sanitize-recover=undefined" test
clean:
	rm -f *.o test_nvpn test_fips_crypto fips_client

FIPS_SRCS = ../src/fips_crypto.c ../src/fips_noise.c ../src/fips_link.c ../src/fips_session.c ../src/fips_mesh.c
test_fips_crypto: test_fips_crypto.c ../src/fips_crypto.c ../src/nvpn_sha256.c ../src/nvpn_core.c $(SECP_OBJS) crypto_vectors.h
	$(CC) $(CFLAGS) test_fips_crypto.c ../src/fips_crypto.c ../src/nvpn_sha256.c ../src/nvpn_core.c $(SECP_OBJS) -o $@
fips-crypto: test_fips_crypto
	./test_fips_crypto

fips_client: ../examples/host-udp/fips_client.c $(SRCS) $(SECP_OBJS)
	$(CC) $(CFLAGS) ../examples/host-udp/fips_client.c $(SRCS) $(SECP_OBJS) -o $@

test_selftest: selftest_host.c ../examples/arduino/SelfTest/selftest_core.h $(SRCS) $(SECP_OBJS)
	$(CC) $(CFLAGS) -D_POSIX_C_SOURCE=200809L selftest_host.c $(SRCS) $(SECP_OBJS) -o $@
selftest: test_selftest
	./test_selftest

TUN_SRCS = ../src/nvpn_tunnel.c
tunnel_ping: tunnel_ping.c $(SRCS) $(TUN_SRCS) $(SECP_OBJS)
	$(CC) $(CFLAGS) -D_DEFAULT_SOURCE tunnel_ping.c $(SRCS) $(TUN_SRCS) $(SECP_OBJS) -o $@
