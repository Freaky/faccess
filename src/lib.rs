#[cfg(unix)]
mod imp {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use libc::{c_int, faccessat, AT_EACCESS, AT_FDCWD, R_OK, W_OK, X_OK};

    fn eaccess(p: &Path, mode: c_int) -> bool {
        unsafe {
            faccessat(
                AT_FDCWD,
                p.as_os_str().as_bytes().as_ptr() as *const i8,
                mode,
                AT_EACCESS,
            ) == 0
        }
    }

    pub fn readable(p: &Path) -> bool {
        eaccess(p, R_OK)
    }

    pub fn writable(p: &Path) -> bool {
        eaccess(p, W_OK)
    }

    pub fn executable(p: &Path) -> bool {
        eaccess(p, X_OK)
    }
}

#[cfg(not(unix))]
mod imp {
    use std::path::Path;

    pub fn readable(p: &Path) -> bool {
        p.exists()
    }

    pub fn writable(p: &Path) -> bool {
        !std::fs::metadata(p)
            .map(|md| md.permissions().readonly())
            .unwrap_or(true)
    }

    pub fn executable(p: &Path) -> bool {
        p.exists()
    }
}

pub trait PathExt {
    fn readable(&self) -> bool;
    fn writable(&self) -> bool;
    fn executable(&self) -> bool;
}

impl PathExt for std::path::Path {
    fn readable(&self) -> bool {
        imp::readable(&self)
    }

    fn writable(&self) -> bool {
        imp::writable(&self)
    }

    fn executable(&self) -> bool {
        imp::executable(&self)
    }
}

#[test]
fn amazing_test_suite() {
    use std::path::PathBuf;

    let path = PathBuf::from("Cargo.toml");
    let notpath = PathBuf::from("Cargo.toml from another dimension");

    #[cfg(unix)]
    {
        assert!(path.readable());
        assert!(path.writable());
        assert!(!path.executable());

        assert!(PathBuf::from("/bin/sh").executable());
    }

    #[cfg(not(unix))]
    {
        assert!(path.readable());
        assert!(path.writable());
        assert!(path.executable());
    }

    assert!(!notpath.readable());
    assert!(!notpath.writable());
    assert!(!notpath.executable());
}
