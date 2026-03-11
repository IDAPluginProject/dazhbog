//! Symbol demangling support backed by `razgad`.

/// Result of demangling attempt
#[derive(Debug, Clone)]
pub struct DemangleResult {
    /// The demangled name (or original if demangling failed)
    pub name: String,
    /// Whether demangling was successful
    pub demangled: bool,
    /// Detected language/mangling scheme
    pub lang: Option<&'static str>,
}

/// Attempt to demangle a symbol name using all known schemes.
/// Returns the demangled name if successful, otherwise the original.
pub fn demangle(name: &str) -> DemangleResult {
    let name = name.trim();

    if name.is_empty() {
        return DemangleResult {
            name: name.to_string(),
            demangled: false,
            lang: None,
        };
    }
    if let Ok(detected) = razgad::heuristic_decode(name) {
        let display = detected.symbol.display();
        let lang = lang_for_symbol(&detected.symbol);
        let demangled = detected.scheme != razgad::Scheme::Plain && display != name;

        if !demangled {
            if let Some(result) = try_legacy_go_middle_dot(name) {
                return result;
            }
        }

        return DemangleResult {
            name: if demangled { display } else { name.to_string() },
            demangled,
            lang,
        };
    }

    if let Some(result) = try_legacy_go_middle_dot(name) {
        return result;
    }

    DemangleResult {
        name: name.to_string(),
        demangled: false,
        lang: None,
    }
}

fn try_legacy_go_middle_dot(name: &str) -> Option<DemangleResult> {
    if !name.contains("·") && !name.contains("%c2%b7") {
        return None;
    }

    let demangled = name
        .replace("·", ".")
        .replace("%c2%b7", ".")
        .replace("%2e", ".");
    let demangled = demangled
        .trim_start_matches("go.")
        .trim_start_matches("type.")
        .to_string();

    if demangled == name {
        return None;
    }

    Some(DemangleResult {
        name: demangled,
        demangled: true,
        lang: Some("go"),
    })
}

fn lang_for_symbol(symbol: &razgad::Symbol) -> Option<&'static str> {
    let scheme = symbol
        .platform
        .inner_scheme
        .unwrap_or(symbol.concrete_family);
    lang_for_scheme(scheme)
}

fn lang_for_scheme(scheme: razgad::Scheme) -> Option<&'static str> {
    match scheme {
        razgad::Scheme::ItaniumCpp
        | razgad::Scheme::BorlandCpp
        | razgad::Scheme::WatcomCpp
        | razgad::Scheme::DigitalMars
        | razgad::Scheme::IbmXlCppLegacy
        | razgad::Scheme::HpAccCppLegacy
        | razgad::Scheme::SunStudioCppLegacy
        | razgad::Scheme::CfrontCpp
        | razgad::Scheme::ArmCppLegacy
        | razgad::Scheme::GreenHillsCpp
        | razgad::Scheme::IntelNativeCpp
        | razgad::Scheme::EdgCppLegacy
        | razgad::Scheme::CrayCpp
        | razgad::Scheme::SgiMipsproCpp
        | razgad::Scheme::MetrowerksCpp
        | razgad::Scheme::CarbonCpp
        | razgad::Scheme::Os400Cpp
        | razgad::Scheme::Vms => Some("c++"),
        razgad::Scheme::MicrosoftCpp => Some("c++/msvc"),
        razgad::Scheme::Cdecl
        | razgad::Scheme::Stdcall
        | razgad::Scheme::Fastcall
        | razgad::Scheme::Vectorcall => Some("c"),
        razgad::Scheme::Pascal | razgad::Scheme::PascalDelphi => Some("pascal"),
        razgad::Scheme::FortranExternal | razgad::Scheme::GfortranModule => Some("fortran"),
        razgad::Scheme::Dlang => Some("d"),
        razgad::Scheme::RustLegacy | razgad::Scheme::RustV0 => Some("rust"),
        razgad::Scheme::Swift => Some("swift"),
        razgad::Scheme::ObjectiveC => Some("objc"),
        razgad::Scheme::Jni => Some("jni"),
        razgad::Scheme::DotNet | razgad::Scheme::UnityIl2Cpp | razgad::Scheme::MonoManaged => {
            Some("managed")
        }
        razgad::Scheme::Haskell => Some("haskell"),
        razgad::Scheme::AdaGnat => Some("ada"),
        razgad::Scheme::Ocaml => Some("ocaml"),
        razgad::Scheme::Go => Some("go"),
        razgad::Scheme::Zig => Some("zig"),
        razgad::Scheme::Nim => Some("nim"),
        razgad::Scheme::Modula => Some("modula"),
        razgad::Scheme::Crystal => Some("crystal"),
        razgad::Scheme::Vlang => Some("v"),
        razgad::Scheme::WebAssembly => Some("wasm"),
        razgad::Scheme::MachO
        | razgad::Scheme::CoffPe
        | razgad::Scheme::Elf
        | razgad::Scheme::Plain => None,
    }
}

/// Demangle a name, returning just the demangled string (or original if failed)
pub fn demangle_simple(name: &str) -> String {
    demangle(name).name
}

/// Check if a name appears to be mangled
pub fn is_mangled(name: &str) -> bool {
    demangle(name).demangled
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_itanium_cpp() {
        let result = demangle("_ZN3foo3barEv");
        assert!(result.demangled);
        assert_eq!(result.lang, Some("c++"));
        assert!(result.name.contains("foo::bar"));
    }

    #[test]
    fn test_msvc_cpp() {
        let result = demangle("?foo@@YAHXZ");
        assert!(result.demangled);
        assert_eq!(result.lang, Some("c++/msvc"));
        assert_ne!(result.name, "?foo@@YAHXZ");
    }

    #[test]
    fn test_rust() {
        let result = demangle("_ZN4core3ptr13drop_in_place17h1234567890abcdefE");
        assert!(result.demangled);
        assert_eq!(result.lang, Some("rust"));
    }

    #[test]
    fn test_not_mangled() {
        let result = demangle("main");
        assert!(!result.demangled);
        assert_eq!(result.name, "main");
    }

    #[test]
    fn test_go_middle_dot() {
        let result = demangle("main·init");
        assert!(result.demangled);
        assert_eq!(result.lang, Some("go"));
        assert_eq!(result.name, "main.init");
    }

    #[test]
    fn test_coff_import_wrapper() {
        let result = demangle("__imp_?alpha@demo@@YAXH@Z");
        assert!(result.demangled);
        assert_eq!(result.lang, Some("c++/msvc"));
        assert!(result.name.contains("import thunk"));
    }

    #[test]
    fn test_plain_name_is_not_demangled() {
        let result = demangle("demo::Widget::run(int)");
        assert!(!result.demangled);
        assert_eq!(result.name, "demo::Widget::run(int)");
    }
}
