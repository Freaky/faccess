#[cfg(unix)]
mod imp {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use libc::{c_int, faccessat, AT_FDCWD, R_OK, W_OK, X_OK};

    // revert once https://github.com/rust-lang/libc/pull/1693 lands
    #[cfg(target_os = "linux")]
    use libc::AT_REMOVEDIR as AT_EACCESS;

    #[cfg(not(target_os = "linux"))]
    use libc::AT_EACCESS;

    fn eaccess(p: &Path, mode: c_int) -> bool {
        let path = CString::new(p.as_os_str().as_bytes()).expect("Path can't contain NULL");
        unsafe { faccessat(AT_FDCWD, path.as_ptr() as *const i8, mode, AT_EACCESS) == 0 }
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
    /// Returns `true` if the path points at a readable entity.
    ///
    /// This function will traverse symbolic links.  In the case of broken
    /// symbolic links it will return `false`.
    ///
    /// This function is best-effort, and on some platforms may simply indicate
    /// the path exists.  Care should be taken not to rely on its result.
    ///
    /// # Platform-specific behaviour
    ///
    /// This function currently corresponds to the [`faccessat`] function in Unix,
    /// with a directory of `AT_FDCWD`, and the `AT_EACCESS` flag to perform the
    /// check against the effective user and group.
    ///
    /// On other platforms it currently delegates to `std::path::Path::exists`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use faccess::PathExt;
    ///
    /// assert_eq!(Path::new("/etc/master.password").readable(), false);
    /// ```
    ///
    /// [`faccessat`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/access.html
    fn readable(&self) -> bool;

    /// Returns `true` if the path points at a writable entity.
    ///
    /// This function will traverse symbolic links.  In the case of broken
    /// symbolic links it will return `false`.
    ///
    /// # Platform-specific behaviour
    ///
    /// This function currently corresponds to the [`faccessat`] function in Unix,
    /// with a directory of `AT_FDCWD`, and the `AT_EACCESS` flag to perform the
    /// check against the effective user and group.
    ///
    /// On other platforms it currently delegates to `std::fs::Permissions::readonly`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use faccess::PathExt;
    ///
    /// assert_eq!(Path::new("/etc/master.password").writable(), false);
    /// ```
    ///
    /// # See Also
    ///
    /// The Rust standard library's `std::fs::Permissions::readonly` method
    /// is this function's inverse.
    ///
    /// [`faccessat`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/access.html
    fn writable(&self) -> bool;

    /// Returns `true` if the path points at an executable entity.
    ///
    /// This function will traverse symbolic links.  In the case of broken
    /// symbolic links it will return `false`.
    ///
    /// This function is best-effort, and on some platforms may simply indicate
    /// the path exists.  Care should be taken not to rely on its result.
    ///
    /// # Platform-specific behaviour
    ///
    /// This function currently corresponds to the [`faccessat`] function in Unix,
    /// with a directory of `AT_FDCWD`, and the `AT_EACCESS` flag to perform the
    /// check against the effective user and group.
    ///
    /// On other platforms it currently delegates to `std::path::Path::exists`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use faccess::PathExt;
    ///
    /// assert_eq!(Path::new("/bin/ls").executable(), true);
    /// ```
    ///
    /// [`faccessat`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/access.html
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
    use std::path::Path;

    let path = Path::new("Cargo.toml");
    let notpath = Path::new("Cargo.toml from another dimension");

    #[cfg(unix)]
    {
        assert!(path.readable());
        assert!(path.writable());
        assert!(!path.executable());

        assert!(Path::new("/bin/sh").executable());
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
