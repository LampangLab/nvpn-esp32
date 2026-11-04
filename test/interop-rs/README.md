# Interop reference node (Rust, real nvpn-fips-core 0.4.107)

    cargo build --release          # needs a recent stable Rust (edition 2024)
    # 1) ping test (C initiates):
    ./target/release/echo echo.yaml <nsec_hex>             # prints its npub; answers ICMP echo requests
    ../tunnel_ping <my_secret_hex> <that npub> 127.0.0.1:2122 12
    # 2) inbound test (Rust node initiates the session towards the C node):
    ./target/release/echo echo.yaml <nsec_hex> <C node npub> <echo_ip> <c_ip>
    ../tunnel_ping <my_secret_hex> <echo npub> 127.0.0.1:2122 12 listen
Mesh IPs are printed by tunnel_ping ("my ip ... peer ip ...", network id "testnet").
