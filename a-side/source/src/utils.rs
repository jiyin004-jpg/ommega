#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppUid(pub i64);

/// `time_t`/`c_long` are i32 on 32-bit ABIs (armv7/i686) and i64 on 64-bit ones, so the
/// fields of a `timespec` need widening before the arithmetic.  Doing it through `Into`
/// is what keeps clippy quiet on both widths: an `as i64` is an unnecessary cast to
/// clippy on 64-bit, and `i64::from` is a useless conversion there.
fn widen(value: impl Into<i64>) -> i64 {
    value.into()
}

/// Whole milliseconds in a `timespec`, widened first so the multiply can't wrap on 32-bit.
pub fn timespec_to_milliseconds(time: libc::timespec) -> i64 {
    widen(time.tv_sec) * 1000 + widen(time.tv_nsec) / 1_000_000
}

/// This returns the current time (in milliseconds) as an instance of a monotonic clock,
/// by invoking the system call since Rust does not support getting monotonic time instance
/// as an integer.
pub fn get_current_time_in_milliseconds() -> i64 {
    let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: The pointer is valid because it comes from a reference, and clock_gettime doesn't
    // retain it beyond the call.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut current_time) };
    timespec_to_milliseconds(current_time)
}

pub trait ParcelExt {
    fn data(&self) -> &[u8];
}

impl ParcelExt for rsbinder::Parcel {
    fn data(&self) -> &[u8] {
        unsafe {
            let data = self.as_ptr();
            let parcel_size = self.data_size();
            std::slice::from_raw_parts(data, parcel_size)
        }
    }
}
