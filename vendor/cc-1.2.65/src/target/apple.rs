use super::TargetInfo;

impl<'a> TargetInfo<'a> {
    pub(crate) fn apple_sdk_name(&self) -> &'static str {
        match (self.os, self.abi, self.env) {
            ("macos", _, _) => "macosx",
            ("ios", "sim", _) | ("ios", _, "sim") => "iphonesimulator",
            ("ios", _, "macabi") => "macosx",
            ("ios", _, _) => "iphoneos",
            ("tvos", "sim", _) | ("tvos", _, "sim") => "appletvsimulator",
            ("tvos", _, _) => "appletvos",
            ("watchos", "sim", _) | ("watchos", _, "sim") => "watchsimulator",
            ("watchos", _, _) => "watchos",
            ("visionos", "sim", _) | ("visionos", _, "sim") => "xrsimulator",
            ("visionos", _, _) => "xros",
            _ => "macosx",
        }
    }

    pub(crate) fn apple_version_flag(&self, min_version: &str) -> String {
        match self.os {
            "macos" => format!("-mmacosx-version-min={min_version}"),
            "ios" if self.env == "macabi" => format!("-mtargetos=ios{min_version}-macabi"),
            "ios" => format!("-miphoneos-version-min={min_version}"),
            "tvos" => format!("-mtvos-version-min={min_version}"),
            "watchos" => format!("-mwatchos-version-min={min_version}"),
            "visionos" => format!("-mtargetos=xros{min_version}"),
            _ => format!("-m{}-version-min={min_version}", self.os),
        }
    }
}
