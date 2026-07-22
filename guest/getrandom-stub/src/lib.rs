//! Stub getrandom for ZiSK zkVM target.
//! ZK proofs are deterministic — real randomness is not needed.

pub use Error as error;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Error(core::num::NonZeroU32);

impl Error {
    pub const UNSUPPORTED: Error =
        Error(unsafe { core::num::NonZeroU32::new_unchecked(0xC000_0000) });

    pub fn code(&self) -> core::num::NonZeroU32 {
        self.0
    }

    pub fn raw_os_error(&self) -> Option<i32> {
        None
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "getrandom stub")
    }
}

impl std::error::Error for Error {}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

pub fn getrandom(buf: &mut [u8]) -> Result<(), Error> {
    buf.fill(0);
    Ok(())
}

pub fn fill(buf: &mut [u8]) -> Result<(), Error> {
    getrandom(buf)
}

pub fn fill_uninit(buf: &mut [core::mem::MaybeUninit<u8>]) -> Result<&mut [u8], Error> {
    let ptr = buf.as_mut_ptr() as *mut u8;
    let len = buf.len();
    unsafe {
        core::ptr::write_bytes(ptr, 0, len);
        Ok(core::slice::from_raw_parts_mut(ptr, len))
    }
}

pub fn u32() -> Result<u32, Error> {
    Ok(0)
}

pub fn u64() -> Result<u64, Error> {
    Ok(0)
}

/// Macro that registers a custom getrandom implementation.
/// In this stub, it's a no-op since we already provide fill().
#[macro_export]
macro_rules! register_custom_getrandom {
    ($fn:ident) => {};
    ($fn:path) => {};
}
