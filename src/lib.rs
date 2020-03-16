#![warn(missing_docs)]

//! `faccess` provides an extension trait for `std::path::Path` which adds
//! `readable`, `writable`, and `executable` methods to test whether the current
//! user (or effective user) is likely to be able to read, write, or execute a
//! given path.
//!
//! This corresponds to the [`faccessat`] function on Unix platforms where
//! available.
//!
//! A custom implementation is included for Windows which attempts to approximate
//! its semantics in a best-effort fashion.
//!
//! On other platforms, a fallback to `std::path::Path::exists` and
//! `std::fs::Permissions::readonly` is used.
//!
//! Care should be taken with these functions not to introduce time-of-check
//! to time-of-use ([TOCTOU]) bugs, and in particular should not be relied upon
//! in a security context.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use faccess::PathExt;
//!
//! let path = Path::new("/bin/sh");
//! assert_eq!(path.readable(), true);
//! assert_eq!(path.writable(), false);
//! assert_eq!(path.executable(), true);
//! ```
//!
//! [`faccessat`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/access.html
//! [TOCTOU]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use

#[cfg(unix)]
mod imp {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use libc::{c_int, faccessat, AT_FDCWD, R_OK, W_OK, X_OK};

    // revert once https://github.com/rust-lang/libc/pull/1693 lands
    #[cfg(target_os = "linux")]
    use libc::AT_REMOVEDIR as AT_EACCESS;

    // Not provided on Android
    #[cfg(target_os = "android")]
    const ET_EACCESS: c_int = 0;

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
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

#[cfg(windows)]
mod imp {
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt};
    use std::path::Path;

    // Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn
    use winapi::shared::minwindef::DWORD;
    use winapi::shared::winerror::ERROR_SUCCESS;
    use winapi::um::accctrl::SE_FILE_OBJECT;
    use winapi::um::aclapi::GetNamedSecurityInfoW;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::processthreadsapi::{GetCurrentThread, OpenThreadToken};
    use winapi::um::securitybaseapi::{
        AccessCheck, GetSidIdentifierAuthority, ImpersonateSelf, IsValidSid, MapGenericMask,
        RevertToSelf,
    };
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{
        SecurityImpersonation, DACL_SECURITY_INFORMATION, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION, HANDLE,
        LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PACL, PRIVILEGE_SET,
        PSECURITY_DESCRIPTOR, PSID, SID_IDENTIFIER_AUTHORITY, TOKEN_DUPLICATE, TOKEN_QUERY,
    };

    struct SecurityDescriptor {
        pub sd: PSECURITY_DESCRIPTOR,
        pub owner: PSID,
        _group: PSID,
        _dacl: PACL,
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            if !self.sd.is_null() {
                unsafe {
                    LocalFree(self.sd as *mut _);
                }
            }
        }
    }

    impl SecurityDescriptor {
        fn for_path(p: &Path) -> std::io::Result<SecurityDescriptor> {
            let path = std::fs::canonicalize(p)?;
            let pathos = path.into_os_string();
            let mut pathw: Vec<u16> = Vec::with_capacity(pathos.len() + 1);
            pathw.extend(pathos.encode_wide());
            pathw.push(0);

            let mut sd = std::ptr::null_mut();
            let mut owner = std::ptr::null_mut();
            let mut group = std::ptr::null_mut();
            let mut dacl = std::ptr::null_mut();

            let err = unsafe {
                GetNamedSecurityInfoW(
                    pathw.as_ptr(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | LABEL_SECURITY_INFORMATION,
                    &mut owner,
                    &mut group,
                    &mut dacl,
                    std::ptr::null_mut(),
                    &mut sd,
                )
            };

            if err == ERROR_SUCCESS {
                Ok(SecurityDescriptor {
                    sd,
                    owner,
                    _group: group,
                    _dacl: dacl,
                })
            } else {
                Err(std::io::Error::last_os_error())
            }
        }
    }

    struct ThreadToken(HANDLE);
    impl Drop for ThreadToken {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    impl ThreadToken {
        fn new() -> std::io::Result<Self> {
            unsafe {
                if ImpersonateSelf(SecurityImpersonation) == 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let mut token: HANDLE = std::ptr::null_mut();
                let err = OpenThreadToken(
                    GetCurrentThread(),
                    TOKEN_DUPLICATE | TOKEN_QUERY,
                    0,
                    &mut token,
                );

                RevertToSelf();

                if err == 0 {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(Self(token))
            }
        }

        // Caller responsible for not dropping while this is used
        unsafe fn as_handle(&self) -> HANDLE {
            self.0
        }
    }

    // Based roughly on Tcl's NativeAccess()
    // https://github.com/tcltk/tcl/blob/2ee77587e4dc2150deb06b48f69db948b4ab0584/win/tclWinFile.c
    fn eaccess(p: &Path, mut mode: DWORD) -> std::io::Result<bool> {
        let md = p.metadata()?;
        // let attr = md.file_attributes();

        if !md.is_dir() {
            // Read Only is ignored for directories
            if mode == FILE_GENERIC_WRITE && md.permissions().readonly() {
                return Ok(false);
            }

            // If it doesn't have the correct extension it isn't executable
            if mode == FILE_GENERIC_EXECUTE {
                if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                    match ext {
                        "exe" | "com" | "bat" | "cmd" => (),
                        _ => return Ok(false),
                    }
                }
            }

            return std::fs::OpenOptions::new()
                .access_mode(mode)
                .open(p)
                .map(|_| true);
        } else if mode == FILE_GENERIC_EXECUTE {
            // You can't execute directories
            return Ok(false);
        }

        let sd = SecurityDescriptor::for_path(p)?;

        // Unmapped Samba users are assigned a top level authority of 22
        // ACL tests are likely to be misleading
        const SAMBA_UNMAPPED: SID_IDENTIFIER_AUTHORITY = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 22],
        };
        unsafe {
            if IsValidSid(sd.owner) != 0
                && (*GetSidIdentifierAuthority(sd.owner)).Value == SAMBA_UNMAPPED.Value
            {
                return Ok(true);
            }
        }

        let token = ThreadToken::new()?;

        let mut ret = false;
        let mut privileges: PRIVILEGE_SET = PRIVILEGE_SET::default();
        let mut granted_access: DWORD = 0;
        let mut privileges_length = std::mem::size_of::<PRIVILEGE_SET>() as u32;
        let mut result = 0;

        let mut mapping = GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        };

        unsafe { MapGenericMask(&mut mode, &mut mapping) };

        if unsafe {
            AccessCheck(
                sd.sd,
                token.as_handle(),
                mode,
                &mut mapping as *mut _,
                &mut privileges as *mut _,
                &mut privileges_length as *mut _,
                &mut granted_access as *mut _,
                &mut result as *mut _,
            ) != 0
        } {
            ret = result != 0;
        }

        Ok(ret)
    }

    pub fn readable(p: &Path) -> bool {
        eaccess(p, FILE_GENERIC_READ).unwrap_or(false)
    }

    pub fn writable(p: &Path) -> bool {
        eaccess(p, FILE_GENERIC_WRITE).unwrap_or(false)
    }

    pub fn executable(p: &Path) -> bool {
        eaccess(p, FILE_GENERIC_EXECUTE).unwrap_or(false)
    }
}

#[cfg(not(any(unix, windows)))]
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

/// Extension trait for `std::path::Path`.
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
    /// On Windows a custom check is performed which attempts to approximate its
    /// semantics.
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
    /// On Windows a custom check is performed which attempts to approximate its
    /// semantics.
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
    /// On Windows a custom check is performed which attempts to approximate its
    /// semantics.
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

    let cargotoml = Path::new("Cargo.toml");

    #[cfg(unix)]
    {
        assert!(cargotoml.readable());
        assert!(cargotoml.writable());
        assert!(!cargotoml.executable());

        let sh = Path::new("/bin/sh");
        assert!(sh.readable());
        assert!(!sh.writable());
        assert!(sh.executable());
    }

    #[cfg(windows)]
    {
        assert!(cargotoml.readable());
        assert!(cargotoml.writable());
        assert!(!cargotoml.executable());

        let notepad = Path::new("C:\\Windows\\notepad.exe");
        assert!(notepad.readable());
        assert!(!notepad.writable());
        assert!(notepad.executable());

        let windows = Path::new("C:\\Windows");
        assert!(windows.readable());
        // Github runs as an Administrator, rendering this test useless there.
        // assert!(!windows.writable());
        assert!(!windows.executable());
    }

    #[cfg(not(any(unix, windows)))]
    {
        assert!(cargotoml.readable());
        assert!(cargotoml.writable());
        assert!(cargotoml.executable());
    }

    let missing = Path::new("Cargo.toml from another dimension");
    assert!(!missing.readable());
    assert!(!missing.writable());
    assert!(!missing.executable());
}
