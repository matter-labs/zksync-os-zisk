//! Hash functions with ZiSK hardware acceleration.
//!
//! On the ZiSK target (`target_os = "zkvm", target_vendor = "zisk"`),
//! keccak256 is routed through `ziskos`'s `native_keccak256` which uses
//! `syscall_keccak_f` — a hardware-accelerated keccak permutation verified
//! via specialized circuits instead of instruction-by-instruction emulation.
//!
//! On native, falls back to `alloy_primitives::keccak256`.

use alloy_primitives::B256;

#[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
unsafe extern "C" {
    /// Provided by `ziskos` entrypoint. Calls `syscall_keccak_f` internally.
    fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8);
}

/// Keccak-256 hash. On ZiSK target, uses hardware-accelerated circuits.
pub fn keccak256(data: &[u8]) -> B256 {
    #[cfg(all(target_os = "zkvm", target_vendor = "zisk"))]
    {
        let mut output = [0u8; 32];
        unsafe { native_keccak256(data.as_ptr(), data.len(), output.as_mut_ptr()) };
        B256::from(output)
    }
    #[cfg(not(all(target_os = "zkvm", target_vendor = "zisk")))]
    {
        alloy_primitives::keccak256(data)
    }
}
