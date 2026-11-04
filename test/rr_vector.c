/* prints a ReceiverReport body for fixed inputs; decode it with the real Rust SessionReceiverReport (see test/interop-rs/rrcheck.rs.txt) */
#include <stdio.h>
#include "fips_internal.h"
int main(void) {
    static fips_session_t s; uint8_t b[66]; int i;
    s.rx_hi = 777; s.rx_pkts = 12; s.rx_bytes = 3456; s.rx_echo_ts = 99999; s.t_rx_ms = 1000; s.rr_last_pkts = 4; s.rr_last_bytes = 1000;
    fips_build_receiver_report(&s, 1250, b);
    for (i = 0; i < 66; i++) printf("%02x", b[i]);
    printf("\n");
    return 0;
}
