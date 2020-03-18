#![warn(missing_docs)]

//! `faccess` provides an extension trait for `std::path::Path` which adds
//! `access`, `readable`, `writable`, and `executable` methods to test whether
//! the current user (or effective user) is likely to be able to read, write,
//! or execute a given path.
//!
//! This corresponds to the [`faccessat`] function on Unix platforms where
//! available.
//!
//! A custom implementation is included for Windows which attempts to approximate
//! its semantics in a best-effort fashion, including but not limited to the use
//! of [`AccessCheck`].
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
//! use faccess::AccessMode;
//!
//! let path = Path::new("/bin/sh");
//! assert_eq!(path.access(AccessMode::READ | AccessMode::EXECUTE).is_ok(), true);
//! assert_eq!(path.readable(), true);
//! assert_eq!(path.writable(), false);
//! assert_eq!(path.executable(), true);
//! ```
//!
//! [`faccessat`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/access.html
//! [`AccessCheck`]: https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck
//! [TOCTOU]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use

use std::io;
use std::path::Path;

use bitflags::bitflags;

bitflags! {
    /// Access mode flags for `access` function to test for.
    pub struct AccessMode: u8 {
        /// Path exists
        const EXISTS  = 0b0001;
        /// Path can likely be read
        const READ    = 0b0010;
        /// Path can likely be written to
        const WRITE   = 0b0100;
        /// Path can likely be executed
        const EXECUTE = 0b1000;
    }
}

#[cfg(unix)]
mod imp {
    use super::*;

    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    use libc::{c_int, faccessat, AT_FDCWD, F_OK, R_OK, W_OK, X_OK};

    // Not provided on Android
    #[cfg(not(target_os = "android"))]
    use libc::AT_EACCESS;

    #[cfg(target_os = "android")]
    const AT_EACCESS: c_int = 0;

    fn eaccess(p: &Path, mode: c_int) -> io::Result<()> {
        let path = CString::new(p.as_os_str().as_bytes()).expect("Path can't contain NULL");
        unsafe {
            if faccessat(AT_FDCWD, path.as_ptr() as *const i8, mode, AT_EACCESS) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn access(p: &Path, mode: AccessMode) -> io::Result<()> {
        let mut imode = 0;

        if mode.contains(AccessMode::EXISTS) {
            imode |= F_OK;
        }

        if mode.contains(AccessMode::READ) {
            imode |= R_OK;
        }

        if mode.contains(AccessMode::WRITE) {
            imode |= W_OK;
        }

        if mode.contains(AccessMode::EXECUTE) {
            imode |= X_OK;
        }

        eaccess(p, imode)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;

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
        fn new() -> io::Result<Self> {
            unsafe {
                if ImpersonateSelf(SecurityImpersonation) == 0 {
                    return Err(io::Error::last_os_error());
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
                    return Err(io::Error::last_os_error());
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
    fn eaccess(p: &Path, mut mode: DWORD) -> io::Result<()> {
        let md = p.metadata()?;

        if !md.is_dir() {
            // Read Only is ignored for directories
            if mode & FILE_GENERIC_WRITE == FILE_GENERIC_WRITE && md.permissions().readonly() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "File is read only",
                ));
            }

            // If it doesn't have the correct extension it isn't executable
            if mode & FILE_GENERIC_EXECUTE == FILE_GENERIC_EXECUTE {
                if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                    match ext {
                        "exe" | "com" | "bat" | "cmd" => (),
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "File not executable",
                            ))
                        }
                    }
                }
            }

            return std::fs::OpenOptions::new()
                .access_mode(mode)
                .open(p)
                .map(|_| ());
        } else if mode & FILE_GENERIC_EXECUTE == FILE_GENERIC_EXECUTE {
            // You can't execute directories
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Directory not executable",
            ));
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
                return Ok(());
            }
        }

        let token = ThreadToken::new()?;

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
            if result == 0 {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Permission Denied",
                ))
            } else {
                Ok(())
            }
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn access(p: &Path, mode: AccessMode) -> io::Result<()> {
        let mut imode = 0;

        if mode.contains(AccessMode::READ) {
            imode |= FILE_GENERIC_READ;
        }

        if mode.contains(AccessMode::WRITE) {
            imode |= FILE_GENERIC_WRITE;
        }

        if mode.contains(AccessMode::EXECUTE) {
            imode |= FILE_GENERIC_EXECUTE;
        }

        if imode == 0 {
            if p.exists() {
                Ok(())
            } else {
                Err(io::Error::new(io::ErrorKind::NotFound, "Not Found"))
            }
        } else {
            eaccess(&p, imode)
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::*;

    pub fn access(p: &Path, mode: AccessMode) -> io::Result<()> {
        if mode.contains(AccessMode::WRITE) {
            if std::fs::metadata(p)?.permissions().readonly() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Path is read only",
                ));
            } else {
                return Ok(());
            }
        }

        if p.exists() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "Path not found"))
        }
    }
}

/// Extension trait for `std::path::Path`.
pub trait PathExt {
    /// Returns `Ok(())` if the path points at an entity which can be accessed
    /// with the given `AccessMode`, otherwise returns an `io::Error` indicating
    /// why the access check failed.
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
    /// On other platforms, a fallback to `std::path::Path::exists` and
    /// `std::fs::Permissions::readonly` is used.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::path::Path;
    /// use faccess::{AccessMode, PathExt};
    ///
    /// // File exists
    /// assert!(Path::new("/bin/sh").access(AccessMode::EXISTS).is_ok());
    ///
    /// // File is readable and executable
    /// assert!(Path::new("/bin/sh").access(AccessMode::READ | AccessMode::EXECUTE).is_ok());
    ///
    /// // File is not writable
    /// assert!(Path::new("/bin/sh").access(AccessMode::WRITE).is_err());
    /// ```
    ///
    /// [`faccessat`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/access.html
    fn access(&self, mode: AccessMode) -> std::io::Result<()>;

    /// Returns `true` if the path points at a readable entity.
    ///
    /// Equivalent to `access(AccessMode::READ).is_ok()`.
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
    fn readable(&self) -> bool {
        self.access(AccessMode::READ).is_ok()
    }

    /// Returns `true` if the path points at a writable entity.
    ///
    /// Equivalent to `access(AccessMode::WRITE).is_ok()`.
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
    fn writable(&self) -> bool {
        self.access(AccessMode::WRITE).is_ok()
    }

    /// Returns `true` if the path points at an executable entity.
    ///
    /// Equivalent to `access(AccessMode::EXECUTE).is_ok()`.
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
    fn executable(&self) -> bool {
        self.access(AccessMode::EXECUTE).is_ok()
    }
}

impl PathExt for Path {
    fn access(&self, mode: AccessMode) -> io::Result<()> {
        imp::access(&self, mode)
    }
}

#[test]
fn amazing_test_suite() {
    let cargotoml = Path::new("Cargo.toml");

    assert!(cargotoml.access(AccessMode::EXISTS).is_ok());
    assert!(cargotoml.access(AccessMode::READ).is_ok());
    assert!(cargotoml
        .access(AccessMode::READ | AccessMode::WRITE)
        .is_ok());

    assert!(cargotoml.readable());
    assert!(cargotoml.writable());

    #[cfg(unix)]
    {
        assert!(!cargotoml.executable());
        assert!(cargotoml
            .access(AccessMode::READ | AccessMode::EXECUTE)
            .is_err());

        let sh = Path::new("/bin/sh");
        assert!(sh.readable());
        assert!(!sh.writable());
        assert!(sh.executable());

        assert!(sh.access(AccessMode::READ | AccessMode::EXECUTE).is_ok());
        assert!(sh.access(AccessMode::READ | AccessMode::WRITE).is_err());
    }

    #[cfg(windows)]
    {
        assert!(!cargotoml.executable());
        assert!(cargotoml
            .access(AccessMode::READ | AccessMode::EXECUTE)
            .is_err());

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
        assert!(cargotoml.executable());
    }

    let missing = Path::new("Cargo.toml from another dimension");
    assert!(missing.access(AccessMode::EXISTS).is_err());
    assert!(!missing.readable());
    assert!(!missing.writable());
    assert!(!missing.executable());
}
