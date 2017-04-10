#![allow(non_camel_case_types)]

use std::os::raw::*;

// krb5/krb5.h:136
pub type krb5_octet = u8;
pub type krb5_int16 = i16;
pub type krb5_ui_2 = u16;
pub type krb5_int32 = i32;
pub type krb5_ui_4  = u32;

pub const VALID_INT_BITS: krb5_int32 = 2147483647;
pub const VALID_UINT_BITS: krb5_ui_4 = 4294967295;

pub const KRB5_INT32_MAX: krb5_int32 = 2147483647;
pub const KRB5_INT32_MIN: krb5_int32 = (-KRB5_INT32_MAX-1);

// not sure, it overflows a signed value, but its like this in
// the orignal source code.
pub const KRB5_INT16_MAX: krb5_int16 = 65535;
pub const KRB5_INT16_MIN: krb5_int16 = (-KRB5_INT16_MAX-1);

// krb5/krb5.h:167
pub const FALSE: krb5_boolean = 0;
pub const TRUE: krb5_boolean = 1;

pub type krb5_boolean = c_uint;
pub type krb5_msgtype = c_uint;
pub type krb5_kvno = c_uint;

pub type krb5_addrtype = krb5_int32;
pub type krb5_enctype = krb5_int32;
pub type krb5_cksumtype = krb5_int32;
pub type krb5_authdatatype = krb5_int32;
pub type krb5_keyusage = krb5_int32;
pub type krb5_cryptotype = krb5_int32;

pub type krb5_preauthtype = krb5_int32;
pub type krb5_flags = krb5_int32;
pub type krb5_timestamp = krb5_int32;
pub type krb5_error_code = krb5_int32;
pub type krb5_deltat = krb5_int32;

pub type krb5_magic = krb5_error_code;

#[repr(C)]
pub struct krb5_data {
    magic: krb5_magic,
    length: c_uint,
    data: *mut c_char,
}

pub const SALT_TYPE_AFS_LENGTH: c_uint = 65535;
pub const SALT_TYPE_NO_LENGTH: c_uint = 65535;

pub type krb5_pointer = *mut c_void;
pub type krb5_const_pointer = *const c_void;

#[repr(C)]
pub struct krb5_principal_data {
    magic: krb5_magic,
    realm: krb5_data,
    /// An array of strings
    data: *mut krb5_data,
    length: krb5_int32,
    type_: krb5_int32,
}

pub type krb5_principal = *mut krb5_principal_data;

/// Name type not known
pub const KRB5_NT_UNKNOWN: krb5_int32 = 0;
/// Just the name of the principal as in DCE, or for users
pub const KRB5_NT_PRINCIPAL: krb5_int32 = 1;
/// Service and ohter unique instance (krbtgt)
pub const KRB5_NT_SRV_INST: krb5_int32 = 2;
/// Service with host name as isntance (telnet, rcommands)
pub const KRB5_NT_SRV_HST: krb5_int32 = 3;
/// Service with host as remaining components
pub const KRB5_NT_SRV_XHST: krb5_int32 = 4;
/// Unique ID
pub const KRB5_NT_UID: krb5_int32 = 5;
/// PKINIT
pub const KRB5_NT_X500_PRINCIPAL: krb5_int32 = 6;
/// Name in form of SMTP email name
pub const KRB5_NT_SMTP_NAME: krb5_int32 = 7;
/// Windows 2000 UPN
pub const KRB5_NT_ENTERPRISE_PRINCIPAL: krb5_int32 = 10;
/// Well-known (special) principal
pub const KRB5_NT_WELLKNOWN: krb5_int32 = 11;
/// First component of NT_WELLKNOWN principals
pub const KRB5_WELLKNOWN_NAMESTR: &'static str = "WELLKNOWN";

/// Windows 2000 UPN and SID
pub const KRB5_NT_MS_PRINCIPAL: krb5_int32 = -128;
/// NT 4 style name
pub const KRB5_NT_MS_PRINCIPAL_AND_ID: krb5_int32 = -129;
/// NT 4 style name and SID
pub const KRB5_NT_ENT_PRINCIPAL_AND_ID: krb5_int32 = -130;

/// Constant version of `krb5_principal_data`
pub type krb5_const_principal = *const krb5_principal_data;

// not sure how to translate these functions since I'm unsure
// about the type of `context`.

// krb5/krb5.h:261
/// Constant for realm referrals
pub const KRB5_REFERRAL_REALM: &'static str = "";

// krb5/krb5.h:267
extern {
    /// Check for a match with KRB5_REFERRAL_REALM
    ///
    /// `r`: Realm to check
    /// returns `TRUE` if `r` is zero-length, `FALSE` otherwise
    pub fn krb5_is_referral_realm(r: *const krb5_data) -> krb5_boolean;
    /// Return an anonymous realm data.
    ///
    /// This function returns constant storage that must not be freed.
    ///
    /// see also: `KRB5_ANONYMOUS_REALMSTR`
    pub fn krb5_anonymous_realm() -> *const krb5_data;
    /// Build an anonymous principal.
    ///
    /// This function returns constant storage that must not be freed.
    ///
    /// see also: `KRB5_ANONYMOUS_PRINCSTR`
    pub fn krb5_anonymous_principal() -> krb5_const_principal;
}

/// Anonymous realm
pub const KRB5_ANONYMOUS_REALMSTR: &'static str = "WELLKNOWN:ANONYMOUS";
/// Anonymous principal name
pub const KRB5_ANONYMOUS_PRINCSTR: &'static str = "ANONYMOUS";

/// Structure for address
#[repr(C)]
pub struct krb5_address {
    magic: krb5_magic,
    addrtype: krb5_addrtype,
    length: c_uint,
    contents: *mut krb5_octet,
}

// krb5/krb5.h:316
pub const ADDRTYPE_INET: krb5_addrtype = 0x0002;
pub const ADDRTYPE_CHAOS: krb5_addrtype = 0x0005;
pub const ADDRTYPE_XNS: krb5_addrtype = 0x0006;
pub const ADDRTYPE_ISO: krb5_addrtype = 0x0007;
pub const ADDRTYPE_DDP: krb5_addrtype = 0x0010;
pub const ADDRTYPE_NETBIOS: krb5_addrtype = 0x0014;
pub const ADDRTYPE_INET6: krb5_addrtype = 0x0018;
pub const ADDRTYPE_ADDRPORT: krb5_addrtype = 0x0100;
pub const ADDRTYPE_IPPORT: krb5_addrtype = 0x0101;

#[allow(non_snake_case)]
pub fn ADDRTYPE_IS_LOCAL(addr: krb5_addrtype) -> bool {
    addr & 0x8000 != 0
}

#[repr(C)]
pub struct _krb5_context;
pub type krb5_context = *mut _krb5_context;

#[repr(C)]
pub struct _krb5_auth_context;
pub type krb5_auth_context = *mut _krb5_auth_context;

#[repr(C)]
pub struct _krb5_cryptosystem_entry;

/// Exposed contents of a key
#[repr(C)]
pub struct krb5_keyblock {
    magic: krb5_magic,
    enctype: krb5_enctype,
    length: c_uint,
    contents: *mut krb5_octet,
}

#[repr(C)]
pub struct krb5_key_st;

/// Opaque identifier for a key.
///
/// Use with the `krb5_k` APIs for better performance for repeated operations with
/// the same key and usage. Key identifiers must not be used simultaneously
/// within multiple threads, as they may contain mutable internal state and are
/// not mutex-protected.
pub type krb5_key = *mut krb5_key_st;

// ifdef KRB5_OLD_CRYPTO
#[cfg(feature = "krb5_old_crypto")]
#[repr(C)]
pub struct krb5_encrypt_block {
    magic: krb5_magic,
    crypto_entry: krb5_enctype,

    key: *mut krb5_keyblock,
}

#[repr(C)]
pub struct krb5_checksum {
    magic: krb5_magic,
    checksum_type: krb5_cksumtype,
    length: c_uint,
    contents: *mut krb5_octet,
}

#[repr(C)]
pub struct krb5_enc_data {
    magic: krb5_magic,
    enctype: krb5_enctype,
    kvno: krb5_kvno,
    ciphertext: krb5_data,
}

/// Structure to describe a region of text to be encrypted or decrypted.
///
/// The `flags` member describes the type of the iov
/// The `data` member points to the memory that will be manipulated.
/// All iov APIs take a ponter to the first element of an array of `krb5_crypto_iov`'s
/// alogn with the size of that array. Buffer contents are manipulated in-place;
/// data is overwritten. Callers must allocate the right numbers of `krb5_crypt_iov`
/// structures before calling into an iov API.
#[repr(C)]
pub struct krb5_crypto_iov {
    /// `KRB5_CRYPTO_TYPE` type of the iov
    flags: krb5_cryptotype,
    data: krb5_data,
}


pub const ENCTYPE_NULL: krb5_enctype = 0x0000;
/// DES cbc mode with CRC-32
pub const ENCTYPE_DES_CBC_CRC: krb5_enctype = 0x0001;
/// DES cbc mode with RSA-MD4
pub const ENCTYPE_DES_CBC_MD4: krb5_enctype = 0x0002;
/// DES cbc mode with RSA-MD5
pub const ENCTYPE_DES_CBC_MD5: krb5_enctype = 0x0003;
/// DES cbc mode raw
#[deprecated]
pub const ENCTYPE_DES_CBC_RAW: krb5_enctype = 0x0004;
/// DES-3 cbc with SHA1
#[deprecated]
pub const ENCTYPE_DES3_CBC_SHA: krb5_enctype = 0x0005;
/// DES-3 cbc mode raw
#[deprecated]
pub const ENCTYPE_DES3_CBC_RAW: krb5_enctype = 0x0006;
#[deprecated]
pub const ENCTYPE_DES_HMAC_SHA1: krb5_enctype = 0x0008;
// PKINIT
/// DSA with SHA1, CMS signature
pub const ENCTYPE_DSA_SHA1_CMS: krb5_enctype = 0x0009;
/// MD5 with RSA, CMS signature
pub const ENCTYPE_MD5_RSA_CMS: krb5_enctype = 0x000a;
