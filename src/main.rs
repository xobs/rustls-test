/// limitedclient: This example demonstrates usage of only ClientConfig::new_custom
/// so that unused cryptography in rustls can be discarded by the linker.  You can
/// observe using `nm` that the binary of this program does not contain any AES code.
use std::sync::Arc;

use std::io::{stdout, Read, Write};
use std::net::TcpStream;

use rustls;
use webpki;
use webpki_roots;

use rustls::Session;

fn main() {
    let mut config = rustls::ClientConfig::with_ciphersuites(&[
        &rustls::ciphersuite::TLS13_CHACHA20_POLY1305_SHA256,
    ]);
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str("google.com").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect("google.com:443").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    tls.write(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: google.com\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}

#[no_mangle]
pub extern "C" fn GFp_bn_mul_mont(
    _rp: usize,
    _ap: usize,
    _bp: usize,
    _np: usize,
    _n0: usize,
    _num: usize,
) {
    // Todo
    ()
}

#[no_mangle]
pub extern "C" fn __assert_func(
    filename: *const std::os::raw::c_char,
    line: std::os::raw::c_int,
    funcname: *const std::os::raw::c_char,
    failedexpr: *const std::os::raw::c_char,
) {
    let func_name = if funcname.is_null() {
        unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(b"\0") }
    } else {
        unsafe { std::ffi::CStr::from_ptr(funcname) }
    };

    let failed_expr = if failedexpr.is_null() {
        unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(b"<invalid expression>\0") }
    } else {
        unsafe { std::ffi::CStr::from_ptr(failedexpr) }
    };

    let file_name = if filename.is_null() {
        unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(b"\0") }
    } else {
        unsafe { std::ffi::CStr::from_ptr(filename) }
    };

    println!(
        "assertion \"{}\" failed: file \"{}\", line {}{}{}\n",
        failed_expr.to_string_lossy(),
        file_name.to_string_lossy(),
        line,
        if funcname.is_null() {
            ""
        } else {
            ", function: "
        },
        func_name.to_string_lossy()
    );
    // abort();
    loop {}
    /* NOTREACHED */
}

#[no_mangle]
pub static mut __stack_chk_guard: std::os::raw::c_long = 0x4662_66DF;

#[no_mangle]
pub extern "C" fn __stack_chk_guard_setup() {
    unsafe { __stack_chk_guard = 0x4662_66DF }; //provide some magic numbers
}

#[no_mangle]
// will be called when guard variable is corrupted
pub extern "C" fn __stack_chk_fail() {
    println!("Stack was corrupted!");
    loop {}
}
