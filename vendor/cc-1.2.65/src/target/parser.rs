use super::TargetInfo;
use crate::{Error, ErrorKind};

#[derive(Debug, Default)]
pub(crate) struct TargetInfoParser;

impl TargetInfoParser {
    pub(crate) fn parse_from_cargo_environment_variables(&self) -> Result<TargetInfo<'static>, Error> {
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH")
            .map_err(|_| Error::new(ErrorKind::EnvVarNotFound, "CARGO_CFG_TARGET_ARCH"))?;
        let vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
        let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "none".to_string());
        let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
        let abi = std::env::var("CARGO_CFG_TARGET_ABI").unwrap_or_default();
        let full_arch = std::env::var("TARGET")
            .ok()
            .and_then(|target| target.split('-').next().map(str::to_owned))
            .unwrap_or_else(|| arch.clone());

        Ok(TargetInfo {
            full_arch: leak(full_arch),
            arch: leak(arch),
            vendor: leak(vendor),
            os: leak(os),
            env: leak(env),
            abi: leak(abi),
        })
    }
}

pub(crate) fn parse_rustc_target(target: &str) -> Result<TargetInfo<'static>, Error> {
    let mut parts = target.split('-');
    let full_arch = parts
        .next()
        .ok_or_else(|| Error::new(ErrorKind::InvalidTarget, "target is empty"))?;
    let vendor = parts.next().unwrap_or("");
    let os = parts.next().unwrap_or("none");
    let rest: Vec<&str> = parts.collect();
    let (env, abi) = match rest.as_slice() {
        [] => ("", ""),
        [env] => (*env, ""),
        [env, abi, ..] => (*env, *abi),
    };
    let arch = match full_arch {
        "i386" | "i586" | "i686" => "x86",
        "armv7" | "armv7s" | "thumbv7em" | "thumbv7m" | "thumbv7neon" => "arm",
        other => other,
    };
    Ok(TargetInfo {
        full_arch: leak(full_arch.to_string()),
        arch: leak(arch.to_string()),
        vendor: leak(vendor.to_string()),
        os: leak(os.to_string()),
        env: leak(env.to_string()),
        abi: leak(abi.to_string()),
    })
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
