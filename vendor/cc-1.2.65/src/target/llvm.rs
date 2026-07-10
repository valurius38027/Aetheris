use std::borrow::Cow;

use super::TargetInfo;
use crate::{Error, ErrorKind};

impl<'a> TargetInfo<'a> {
    pub(crate) fn from_rustc_target(target: &str) -> Result<TargetInfo<'static>, Error> {
        super::parser::parse_rustc_target(target)
    }

    pub(crate) fn llvm_target<'b>(&self, raw_target: &'b Cow<'b, str>, version: Option<&str>) -> String {
        if let Some(version) = version {
            if self.os == "visionos" || self.env == "macabi" {
                return format!("{}-{}", raw_target, version);
            }
        }
        raw_target.to_string()
    }

    #[allow(dead_code)]
    pub(crate) fn ensure_known(&self) -> Result<(), Error> {
        if self.arch.is_empty() {
            Err(Error::new(ErrorKind::UnknownTarget, "target architecture is empty"))
        } else {
            Ok(())
        }
    }
}
