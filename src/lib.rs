use std::ffi::{ CStr };
use std::mem::{ size_of };
use std::ptr::{ null_mut };
use std::slice;
use libc::{ c_char, c_int, size_t, hostent, in_addr, in6_addr };
use libc::{ ENOENT, ERANGE, AF_INET, AF_INET6 };

enum NSSStatus {
    // TryAgain = -2,
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
    h_errnop: &mut i32
) -> i32 {
    let parsed_name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            *errnop = ENOENT;
            return NSSStatus::NotFound as i32;
        }
    };

    if buf.is_null() || buflen < size_of::<*mut in6_addr>() * 2 + size_of::<in6_addr>() {
        *errnop = ERANGE;
    }

    if parsed_name == "MagicHost" {
        match family {
            AF_INET => fill_result_with_ipv4_address(name, result_buf, buf, 0x0102007F),
            AF_INET6 => fill_result_with_ipv6_address(name, result_buf, buf, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            _ => {
                *errnop = ENOENT;
                return NSSStatus::Unavailable as i32;
            }
        }

        return NSSStatus::Success as i32;
    } else {
        *errnop = ENOENT;
        // *h_errnop = 1; // HOST_NOT_FOUND
        return NSSStatus::NotFound as i32;
    }
}

fn fill_result_with_ipv4_address(name: *const c_char, result_buf: *mut hostent, buf: *mut c_char, address: u32) {
    // buf +0   addr_list[0] = buf + 2
    // buf +1   addr_list[1] = null
    // buf +2                = addr
    unsafe {
        let addr_list = slice::from_raw_parts_mut(buf as *mut *mut in_addr, 3);
        addr_list[0] = &mut addr_list[2] as *mut *mut in_addr as *mut in_addr;
        addr_list[1] = null_mut();
        let addr = &mut *addr_list[0];
        addr.s_addr = address;

        let result_buf = &mut *result_buf;
        result_buf.h_name = name as *mut c_char;
        result_buf.h_aliases = null_mut();
        result_buf.h_addrtype = AF_INET;
        result_buf.h_length = 4;
        result_buf.h_addr_list = buf as *mut *mut c_char;
    }
}

fn fill_result_with_ipv6_address(name: *const c_char, result_buf: *mut hostent, buf: *mut c_char, address: [u8; 16]) {
    // buf +0   addr_list[0] = buf + 2
    // buf +1   addr_list[1] = null
    // buf +2                = addr
    unsafe {
        let addr_list = slice::from_raw_parts_mut(buf as *mut *mut in6_addr, 3);
        addr_list[0] = &mut addr_list[2] as *mut *mut in6_addr as *mut in6_addr;
        addr_list[1] = null_mut();
        let addr = &mut *addr_list[0];
        addr.s6_addr = address;

        let result_buf = &mut *result_buf;
        result_buf.h_name = name as *mut c_char;
        result_buf.h_aliases = null_mut();
        result_buf.h_addrtype = AF_INET6;
        result_buf.h_length = 16;
        result_buf.h_addr_list = buf as *mut *mut c_char;
    }
}
