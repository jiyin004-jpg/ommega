#![recursion_limit = "256"]

// 默认的 bionic malloc 在多线程下竞争很明显，换 mimalloc：每线程一个堆、无全局锁。
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    ommega::cli_main();
}
