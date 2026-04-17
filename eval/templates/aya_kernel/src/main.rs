#![no_std] #![no_main] use aya_ebpf::macros::xdp; use aya_ebpf::programs::XdpContext; #[xdp] pub fn xdp_prog(_ctx: XdpContext) -> u32 { 0 }
