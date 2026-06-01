use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Initialize tracing — call once at program start.
/// Checks the AETHERIS_TRACE environment variable.
pub fn init() {
    TRACE_ENABLED.store(std::env::var("AETHERIS_TRACE").is_ok(), Ordering::Relaxed);
}

/// Check if tracing is enabled (cheap atomic read).
pub fn enabled() -> bool {
    TRACE_ENABLED.load(Ordering::Relaxed)
}

/// Print a trace message if tracing is enabled.
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        if $crate::trace::enabled() {
            eprintln!($($arg)*);
        }
    };
}

/// Print a trace message prefixed with elapsed ms since `start`.
#[macro_export]
macro_rules! trace_elapsed {
    ($start:expr, $($arg:tt)*) => {
        if $crate::trace::enabled() {
            let _now = std::time::Instant::now();
            eprintln!("[{:>8.3}ms] {}", _now.duration_since($start).as_secs_f64() * 1000.0, format_args!($($arg)*));
        }
    };
}

/// Helper to create a named timer at trace scope.
pub fn now() -> Instant {
    Instant::now()
}
