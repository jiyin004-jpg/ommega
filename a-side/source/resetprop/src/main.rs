mod resetprop_main;

fn main() {
    resetprop_main::resetprop_main(&std::env::args().collect::<Vec<_>>())
}
