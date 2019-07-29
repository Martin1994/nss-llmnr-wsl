use std::ffi::CStr;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};
use std::ptr::null_mut;
use std::slice;
use std::str;
use libc::{c_char, c_int, size_t, hostent, in_addr, in6_addr};
use libc::{ENOENT, ERANGE, AF_INET, AF_INET6};

enum NssStatus {
    TryAgain = -2,
    Unavailable = -1,
    NotFound = 0,
    Success = 1
}

#[no_mangle]
pub extern "C" fn _nss_llmnr_wsl_gethostbyname_r(
    name: *const c_char,
    result_buf: *mut hostent,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut i32,
    h_errnop: *mut i32
) -> i32 {
    unsafe {
        return llmnr_wsl_gethostbyname_impl(name, AF_INET, result_buf, buf, buflen, &mut *errnop, &mut *h_errnop);
    }
}

#[no_mangle]
pub extern "C" fn _nss_llmnr_wsl_gethostbyname2_r(
    name: *const c_char,
    family: c_int,
    result_buf: *mut hostent,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut i32,
    h_errnop: *mut i32
) -> i32 {
    unsafe {
        return llmnr_wsl_gethostbyname_impl(name, family, result_buf, buf, buflen, &mut *errnop, &mut *h_errnop)
    }
}

fn llmnr_wsl_gethostbyname_impl(
    name: *const c_char,
    family: c_int,
    result_buf: *mut hostent,
    buf: *mut c_char,
    buflen: size_t,
    errnop: &mut i32,
    _h_errnop: &mut i32
) -> i32 {
    let parsed_name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            return nss_not_found(errnop);
        }
    };

    if buf.is_null() || buflen < size_of::<*mut in6_addr>() * 2 + size_of::<in6_addr>() {
        return nss_insufficient_buffer_range(errnop);
    }

    match family {
        AF_INET => {
            if let Ok(address) = query_ipv4_address_from_powershell(parsed_name) {
                fill_result_with_ipv4_address(name, result_buf, buf, address);
                return nss_success(errnop);
            }
        },
        AF_INET6 => {
            if let Ok(address) = query_ipv6_address_from_powershell(parsed_name) {
                fill_result_with_ipv6_address(name, result_buf, buf, address);
                return nss_success(errnop);
            }
        },
        _ => {
            return nss_unavailable(errnop)
        }
    }

    return nss_not_found(errnop);
}

fn nss_insufficient_buffer_range(errnop: &mut i32) -> i32 {
    *errnop = ERANGE;
    return NssStatus::TryAgain as i32;
}

fn nss_unavailable(errnop: &mut i32) -> i32 {
    *errnop = ENOENT;
    return NssStatus::Unavailable as i32;
}

fn nss_not_found(errnop: &mut i32) -> i32 {
    *errnop = ENOENT;
    // *h_errnop = 1; // HOST_NOT_FOUND
    return NssStatus::NotFound as i32;
}

fn nss_success(_errnop: &mut i32) -> i32 {
    return NssStatus::Success as i32;
}

fn query_ipv4_address_from_powershell(name: &str) -> Result<Ipv4Addr, ()> {
    if let Ok(address_str) = query_address_string_from_powershell(name, "A") {
        if let Ok(address) = address_str.parse() {
            return Ok(address);
        }
    }

    return Err(());
}

fn query_ipv6_address_from_powershell(name: &str) -> Result<Ipv6Addr, ()> {
    if let Ok(address_str) = query_address_string_from_powershell(name, "AAAA") {
        if let Ok(address) = address_str.parse() {
            return Ok(address);
        }
    }

    return Err(());
}

fn query_address_string_from_powershell(name: &str, address_type: &str) -> Result<String, ()> {
    let output = Command::new("powershell.exe")
        .arg("-Command")
        .arg(format!(
            "try {{ (Resolve-DnsName -Name {0} -Type {1} -LlmnrOnly -ErrorAction Stop).IPAddress; }} catch {{ exit 1; }}",
            name,
            address_type))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            if let Ok(mut address_str) = String::from_utf8(output.stdout) {
                address_str.pop();
                address_str.pop();
                return Ok(address_str)
            }
        }
    }

    return Err(());
}

fn fill_result_with_ipv4_address(name: *const c_char, result_buf: *mut hostent, buf: *mut c_char, address: Ipv4Addr) {
    // buf +0   addr_list[0] = buf + 2
    // buf +1   addr_list[1] = null
    // buf +2                = in_addr
    unsafe {
        let addr_list = slice::from_raw_parts_mut(buf as *mut *mut in_addr, 3);
        addr_list[0] = &mut addr_list[2] as *mut *mut in_addr as *mut in_addr;
        addr_list[1] = null_mut();
        let addr = &mut *addr_list[0];
        let address_host_bytes: u32 = address.into();
        addr.s_addr = address_host_bytes.to_be();

        let result_buf = &mut *result_buf;
        result_buf.h_name = name as *mut c_char;
        result_buf.h_aliases = null_mut();
        result_buf.h_addrtype = AF_INET;
        result_buf.h_length = 4;
        result_buf.h_addr_list = buf as *mut *mut c_char;
    }
}

fn fill_result_with_ipv6_address(name: *const c_char, result_buf: *mut hostent, buf: *mut c_char, address: Ipv6Addr) {
    // buf +0   addr_list[0] = buf + 2
    // buf +1   addr_list[1] = null
    // buf +2                = in6_addr
    unsafe {
        let addr_list = slice::from_raw_parts_mut(buf as *mut *mut in6_addr, 3);
        addr_list[0] = &mut addr_list[2] as *mut *mut in6_addr as *mut in6_addr;
        addr_list[1] = null_mut();
        let addr = &mut *addr_list[0];
        addr.s6_addr = address.octets();

        let result_buf = &mut *result_buf;
        result_buf.h_name = name as *mut c_char;
        result_buf.h_aliases = null_mut();
        result_buf.h_addrtype = AF_INET6;
        result_buf.h_length = 16;
        result_buf.h_addr_list = buf as *mut *mut c_char;
    }
}
