[![Cargo](https://img.shields.io/crates/v/faccess.svg)][crate] 
![](https://github.com/Freaky/faccess/workflows/Continuous%20Integration/badge.svg)

# faccess

Basic file accessibility checks for Rust.

## Synopsis

```rust
use std::path::Path;
use faccess::PathExt;

let path = Path::new("/bin/ls");
assert!(path.readable());
assert!(!path.writable());
assert!(path.executable());
```

On Unix, this uses [`faccessat(2)`] with `AT_EACCESS` to check against the
effective user and group ID's, on other platforms it simply proxies to
`exists()` and `readonly()` as appropriate.


## Caveats

Beware not to introduce any serious time-of-check to time-of-use ([TOCTOU])
bugs with these functions.  They are strictly best-effort and are absolutely not
alternatives to checking to see if opening a file or launching a program actually
succeeded.

[`faccessat(2)`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/access.html
[TOCTOU]: https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use
[crate]: https://crates.io/crates/faccess
