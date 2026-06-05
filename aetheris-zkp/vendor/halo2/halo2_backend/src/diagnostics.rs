use std::sync::OnceLock;

fn dbg_enabled_impl() -> bool {
    std::env::var("AETHERIS_DBG").is_ok()
}

pub fn dbg_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(dbg_enabled_impl)
}
