#![no_std]
#![no_main]

// Compiled to BPF bytecode; loaded by the userspace axion-capture binary.
// Counts inbound packets per destination IPv4 address in a BPF hash map.
// The userspace agent polls that map each second and feeds the counts into
// the Rust DdosDetector.
//
// Build:
//   cargo build -p axion-capture-ebpf --release --target bpfel-unknown-none \
//               -Z build-std=core

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;

/// dst_ip (big-endian u32) → packet count
#[map]
static PKT_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_ddos_probe(ctx: XdpContext) -> u32 {
    match classify(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn classify(ctx: &XdpContext) -> Result<u32, ()> {
    // Ethernet header — 14 bytes
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    // Only handle IPv4 (ethertype 0x0800, stored BE → 0x0008 on little-endian)
    if unsafe { (*eth).ether_type } != 0x0008u16 {
        return Ok(xdp_action::XDP_PASS);
    }

    // IPv4 header starts at offset 14
    let ip: *const IpHdr = ptr_at(ctx, EthHdr::LEN)?;
    let dst = unsafe { (*ip).dst_addr }; // already BE u32

    // Atomic-like increment in the BPF map
    unsafe {
        if let Some(cnt) = PKT_COUNTS.get_ptr_mut(&dst) {
            *cnt += 1;
        } else {
            let _ = PKT_COUNTS.insert(&dst, &1u64, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

// Minimal header definitions (avoid pulling in kernel headers)

#[repr(C)]
struct EthHdr {
    _dst: [u8; 6],
    _src: [u8; 6],
    ether_type: u16,
}

impl EthHdr {
    const LEN: usize = mem::size_of::<Self>();
}

#[repr(C)]
struct IpHdr {
    _ver_ihl:  u8,
    _tos:      u8,
    _tot_len:  u16,
    _id:       u16,
    _frag_off: u16,
    _ttl:      u8,
    _proto:    u8,
    _check:    u16,
    _src_addr: u32,
    dst_addr:  u32,
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
