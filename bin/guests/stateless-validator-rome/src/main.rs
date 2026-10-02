#![no_main]
ziskos::entrypoint!(main);

fn main() {
    guest_rome::run();
}
