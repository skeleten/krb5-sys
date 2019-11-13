#![allow(non_camel_case_types, non_upper_case_globals, overflowing_literals)]

pub mod plugin;

use std::os::raw::*;

// krb5/krb5.h:136

pub enum _profile_t {}

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
    pub magic: krb5_magic,
    pub length: c_uint,
    pub data: *mut c_char,
}

#[repr(C)]
pub struct krb5_octet_data {
    pub magic: krb5_magic,
    pub length: c_uint,
    pub data: *mut krb5_octet,
}

pub const SALT_TYPE_AFS_LENGTH: c_uint = 65535;
pub const SALT_TYPE_NO_LENGTH: c_uint = 65535;

pub type krb5_pointer = *mut c_void;
pub type krb5_const_pointer = *const c_void;

#[repr(C)]
pub struct krb5_principal_data {
    pub magic: krb5_magic,
    pub realm: krb5_data,
    /// An array of strings
    pub data: *mut krb5_data,
    pub length: krb5_int32,
    pub type_: krb5_int32,
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
#[link(name = "krb5")]
extern "C" {
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
    pub magic: krb5_magic,
    pub addrtype: krb5_addrtype,
    pub length: c_uint,
    pub contents: *mut krb5_octet,
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

pub enum _krb5_context {}
pub type krb5_context = *mut _krb5_context;

pub enum _krb5_auth_context {}
pub type krb5_auth_context = *mut _krb5_auth_context;

pub enum _krb5_cryptosystem_entry {}

/// Exposed contents of a key
#[repr(C)]
pub struct krb5_keyblock {
    pub magic: krb5_magic,
    pub enctype: krb5_enctype,
    pub length: c_uint,
    pub contents: *mut krb5_octet,
}

pub enum krb5_key_st {}

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
    pub magic: krb5_magic,
    pub crypto_entry: krb5_enctype,

    pub key: *mut krb5_keyblock,
}

#[repr(C)]
pub struct krb5_checksum {
    pub magic: krb5_magic,
    pub checksum_type: krb5_cksumtype,
    pub length: c_uint,
    pub contents: *mut krb5_octet,
}

#[repr(C)]
pub struct krb5_enc_data {
    pub magic: krb5_magic,
    pub enctype: krb5_enctype,
    pub kvno: krb5_kvno,
    pub ciphertext: krb5_data,
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
    pub flags: krb5_cryptotype,
    pub data: krb5_data,
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
/// SHA1 with RSA, CMS signature
pub const ENCTYPE_SHA1_RSA_CMS: krb5_enctype = 0x000b;
/// RC2 cbc mode, CMS enveloped data
pub const ENCTYPE_RC2_CBC_ENV: krb5_enctype = 0x000c;
/// RSA encryption, CMS enveloped data
pub const ENCTYPE_RSA_ENV: krb5_enctype = 0x000d;
/// RSA w/OEAP encryption, CMS enveloped data
pub const ENCTYPE_RSA_ES_OAEP_ENV: krb5_enctype = 0x000e;
/// DES-3 cbc mode, CMS enveloped data
pub const ENCTYPE_DES3_CBC_ENV: krb5_enctype = 0x000f;

pub const ENCTYPE_DES3_CBC_SHA1: krb5_enctype = 0x0010;
/// RFC 3962
pub const ENCTYPE_AES128_CTS_HMAC_SHA1_96: krb5_enctype = 0x0011;
/// RFC 3962
pub const ENCTYPE_AES256_CTS_HMAC_SHA1_96: krb5_enctype = 0x0012;
pub const ENCTYPE_ARCFOUR_HMAC: krb5_enctype = 0x0017;
pub const ENCTYPE_ARCFOUR_HMAC_EXP: krb5_enctype = 0x0018;
/// RFC 6803
pub const ENCTYPE_CAMELLIA128_CTS_CMAC: krb5_enctype = 0x0019;
/// RFC 6803
pub const ENCTYPE_CAMELLIA256_CTS_CMAC: krb5_enctype = 0x001a;
pub const ENCTYPE_UNKNOWN: krb5_enctype = 0x01ff;

pub const CKSUMTYPE_CRC32: krb5_cksumtype = 0x0001;
pub const CKSUMTYPE_RSA_MD4: krb5_cksumtype = 0x0002;
pub const CKSUMTYPE_RSA_MD4_DES: krb5_cksumtype = 0x0003;
pub const CKSUMTYPE_DESCBC: krb5_cksumtype = 0x0004;
pub const CKSUMTYPE_RSA_MD5: krb5_cksumtype = 0x0007;
pub const CKSUMTYPE_RSA_MD5_DES: krb5_cksumtype = 0x0008;
pub const CKSUMTYPE_NIST_SHA: krb5_cksumtype = 0x0009;
pub const CKSUMTYPE_HMAC_SHA1_DES3: krb5_cksumtype = 0x000c;
/// RFC 3962. Used with `ENCTYPE_AES128_CTS_HMAC_SHA1_96`
pub const CKSUMTYPE_HMAC_SHA1_96_AES128: krb5_cksumtype = 0x000f;
/// RFC 3962. Used with `ENCTYPE_AES256_CTS_HMAC_SHA1_96`
pub const CKSUMTYPE_HMAC_SHA1_96_AES256: krb5_cksumtype = 0x0010;
/// RFC 6803.
pub const CKSUMTYPE_CMAC_CAMELLIA128: krb5_cksumtype = 0x0011;
/// RFC 6803
pub const CKSUMTYPE_CMAC_CAMELLIA256: krb5_cksumtype = 0x0012;
/// Microsoft netlogon cksumtype
pub const CKSUMTYPE_MD5_HMAC_ARCFOUR: krb5_cksumtype = -137;
/// Micorsoft md5 hmac cksumtype
pub const CKSUMTYPE_HMAC_MD5_ARCFOUR: krb5_cksumtype = -138;

// A wild enum appears!
pub const KRB5_C_RANDSOURCE_OLDAPI: u32 = 0;
pub const KRB5_C_RANDSORUCE_OSRAND: u32 = 1;
pub const KRB5_C_RANDSOURCE_TRUSTEDPARTY: u32 = 2;
pub const KRB5_C_RANDSOURCE_TIMING: u32 = 3;
pub const KRB5_C_RANDSOURCE_EXTERNAL_PROTOCOL: u32 = 4;
pub const KRB5_C_RANDSOURCE_MAX: u32 = 5;

// TODO: krb5_roundup
//       krb5_x
//       krb5_xc

#[link(name = "krb5")]
extern "C" {
    /// Encrypt data using a key (operates on keyblock).
    ///
    /// `context`: Library context
    /// `key`: Encryption key
    /// `usage`: Key usage (see `KRB5_KEYUSAGE` types)
    /// `cipher_state`: Cipher state; specify `NULL` if not needed.
    /// `input`: Data to be encrypted
    /// `output`: Encrypted data.
    ///
    /// This function encrypts the data block `input` and stores the output into
    /// `output`. The actual encryption key will be derived from `key` and `usage`
    /// if key derivation is specified for the encryption type. If non-null,
    /// `cipher_state` specifies the beginning state for the encryption operation,
    /// and is updated with the state to be passed as input to the next operation.
    ///
    /// Note: the caller must initialize `output` and allocate at least enough
    /// space for the result (using `krb5_c_encrypt_length()` to determine the amount
    /// of space needed). `output.length` will be set to the actual length of the
    /// ciphertetxt.
    ///
    /// returns `0` on success, otherwise - Kerberos error codes
    pub fn krb5_c_encrypt(context: krb5_context,
                          key: *const krb5_keyblock,
                          usage: krb5_keyusage,
                          cipher_state: *const krb5_data,
                          input: *const krb5_data,
                          output: *mut krb5_enc_data) -> krb5_error_code;

    /// Decrypt data using a key (operates on keyblock)
    ///
    /// `context`: Library context
    /// `key`: Encryption key
    /// `usage`: Key usage (see `KRB5_KEYUSAGE` types)
    /// `cipher_state`: Cipher state; specify NULL if not needed.
    /// `input`: Encrypted data
    /// `output`: Decrypted data
    ///
    /// This function decryptes the data block `input` and stores the output into
    /// `output`. The actual decryption key will be derived from `key` and `usage`
    /// if key derivation is specified for the encryption type. If non-null,
    /// `cipher_state` specifies the beginning state for the decryption operation,
    /// and is updated with the state to be passed as input to the next operation.
    ///
    /// Note: The caller must initialize `output` and allocate at least enough
    /// space for the result. The usual practice is to allocate an output buffer as
    /// long as the ciphertext, and let `krb5_c_decrypt()` trim `output.length`.
    /// For some enctypes, the resulting `output.length` may include padding bytes.
    ///
    /// returns 0 on success, kerberos error codes otherwise.
    pub fn krb5_c_decrypt(context: krb5_context,
                          key: *const krb5_keyblock,
                          usage: krb5_keyusage,
                          cipher_state: *const krb5_data,
                          input: *const krb5_enc_data,
                          output: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_encrypt_length(context: krb5_context,
                                 enctype: krb5_enctype,
                                 inputlen: usize,
                                 length: *mut usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_block_size(context: krb5_context,
                             enctype: krb5_enctype,
                             blocksize: *mut usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_keylengths(context: krb5_context,
                             enctype: krb5_enctype,
                             keybytes: *mut usize,
                             keylength: *mut usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_init_state(context: krb5_context,
                             key: *const krb5_keyblock,
                             usage: krb5_keyusage,
                             new_state: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb_c_free_state(context: krb5_context,
                            key: *const krb5_keyblock,
                            state: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_prf(context: krb5_context,
                      keyblock: *const krb5_keyblock,
                      input: *mut krb5_data,
                      output: *mut krb5_data)-> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_prf_length(context: krb5_context,
                             enctype: krb5_enctype,
                             len: *mut usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_fx_cf2_simple(context: krb5_context,
                                k1: *mut krb5_keyblock,
                                pepper1: *const c_char,
                                k2: *mut krb5_keyblock,
                                pepper2: *const c_char,
                                out: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_make_random_key(context: krb5_context,
                                  enctype: krb5_enctype,
                                  k5_random_key: *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_random_to_key(context: krb5_context,
                                enctype: krb5_enctype,
                                random_data: *mut krb5_data,
                                k5_random_key: *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_random_add_entropy(context: krb5_context,
                                     randsource: c_uint,
                                     data: *const krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_random_make_octets(context: krb5_context,
                                     data: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_random_os_entropy(context: krb5_context,
                                    strong: c_int,
                                    success: *mut c_int) -> krb5_error_code;
    // TODO: Doc
    #[deprecated]
    pub fn krb5_c_random_seed(context: krb5_context,
                              data: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_string_to_key(context: krb5_context,
                                enctype: krb5_enctype,
                                string: *const krb5_data,
                                salt: *const krb5_data,
                                key: *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_string_to_key_with_params(context: krb5_context,
                                            enctype: krb5_enctype,
                                            string: *const krb5_data,
                                            salt: *const krb5_data,
                                            params: *const krb5_data,
                                            key: *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_enctype_compare(context: krb5_context,
                                  e1: krb5_enctype,
                                  e2: krb5_enctype,
                                  similiar: *mut krb5_boolean) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_make_checksum(context: krb5_context,
                                cksumtype: krb5_cksumtype,
                                key: *const krb5_keyblock,
                                usage: krb5_keyusage,
                                input: *const krb5_data,
                                cksum: *mut krb5_checksum) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_verify_checksum(context: krb5_context,
                                  key: *const krb5_keyblock,
                                  usage: krb5_keyusage,
                                  data: *const krb5_data,
                                  cksum: *const krb5_checksum,
                                  valid: *mut krb5_boolean) -> krb5_error_code;
    // TODO Doc
    pub fn krb5_c_checksum_length(context: krb5_context,
                                  cksumtype: krb5_cksumtype,
                                  length: *mut usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_keyed_checksum_types(context: krb5_context,
                                       enctype: krb5_enctype,
                                       count: *mut c_uint,
                                       cksumtypes: *mut *mut krb5_cksumtype) -> krb5_error_code;
}

pub const KRB5_KEYUSAGE_AS_REQ_PA_ENC_TS: krb5_keyusage = 1;
pub const KRB5_KEYUSAGE_KDC_REP_TICKET: krb5_keyusage = 2;
pub const KRB5_KEYUSAGE_AS_REP_ENCPART: krb5_keyusage = 3;
pub const KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY: krb5_keyusage = 4;
pub const KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY: krb5_keyusage = 5;
pub const KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM: krb5_keyusage = 6;
pub const KRB5_KEYUSAGE_TGS_REQ_AUTH: krb5_keyusage = 7;
pub const KRB5_KEYUSAGE_TGS_REP_ENCPART_SESSKEY: krb5_keyusage = 8;
pub const KRB5_KEYUSAGE_TGS_REP_ENCPART_SUBKEY: krb5_keyusage = 9;
pub const KRB5_KEYUSAGE_AP_REQ_AUTH_CKSUM: krb5_keyusage = 10;
pub const KRB5_KEYUSAGE_AP_REQ_AUTH: krb5_keyusage = 11;
pub const KRB5_KEYUSAGE_AP_REP_ENCPART: krb5_keyusage = 12;
pub const KRB5_KEYUSAGE_KRB_PRIV_ENCPART: krb5_keyusage = 13;
pub const KRB5_KEYUSAGE_KRB_CRED_ENCPART: krb5_keyusage = 14;
pub const KRB5_KEYUSAGE_KRB_SAFE_CKSUM: krb5_keyusage = 15;
pub const KRB5_KEYUSAGE_APP_DATA_ENCRYPT: krb5_keyusage = 16;
pub const KRB5_KEYUSAGE_APP_DATA_CKSUM: krb5_keyusage = 17;
pub const KRB5_KEYUSAGE_KRB_ERROR_CKSUM: krb5_keyusage = 18;
pub const KRB5_KEYUSAGE_AD_KDCISSUED_CKSUM: krb5_keyusage = 19;
pub const KRB5_KEYUSAGE_AD_MTE: krb5_keyusage = 20;
pub const KRB5_KEYUSAGE_AD_ITE: krb5_keyusage = 21;

pub const KRB5_KEYUSAGE_GSS_TOK_MIC: krb5_keyusage = 22;
pub const KRB5_KEYUSAGE_GSS_TOK_WRAP_INTEG: krb5_keyusage = 23;
pub const KRB5_KEYUSAGE_GSS_TOK_WRAP_PRIV: krb5_keyusage = 24;
pub const KRB5_KEYUSAGE_PA_SAM_CHALLENGE_CKSUM: krb5_keyusage = 25;
/// Note conflict with `KRB5_KEYUSAGE_PA_SAM_CHALLENGE_TRAKCID`
pub const KRB5_KEYUSAGE_PA_S4U_X509_USER_REQUEST: krb5_keyusage = 26;
// Note conflict with `KRB5_KEYUSAGE_PA_SAM_RESPONSE`
pub const KRB5_KEYUSAGE_PA_S4U_X509_USER_REPLY: krb5_keyusage = 27;
pub const KRB5_KEYUSAGE_PA_REFERRAL: krb5_keyusage = 26;

pub const KRB5_KEYUSAGE_AD_SIGNEDPATH: krb5_keyusage = -21;
pub const KRB5_KEYUSAGE_IAKERB_FINISHED: krb5_keyusage = 42;
pub const KRB5_KEYUSAGE_PA_PKINIT_KX: krb5_keyusage = 44;
/// See RFC 6560 section 4.2
pub const KRB5_KEYUSAGE_PA_OTP_REQUEST: krb5_keyusage = 45;
pub const KRB5_KEYUSAGE_FAST_REQ_CHKSUM: krb5_keyusage = 50;
pub const KRB5_KEYUSAGE_FAST_ENC: krb5_keyusage = 51;
pub const KRB5_KEYUSAGE_FAST_REP: krb5_keyusage = 52;
pub const KRB5_KEYUSAGE_FAST_FINISHED: krb5_keyusage = 53;
pub const KRB5_KEYUSAGE_ENC_CHALLENGE_CLIENT: krb5_keyusage = 54;
pub const KRB5_KEYUSAGE_ENC_CHALLENGE_KDC: krb5_keyusage = 55;
pub const KRB5_KEYUSAGE_AS_REQ: krb5_keyusage = 56;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_c_valid_enctype(ktype: krb5_enctype) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_c_valid_cksumtype(ctype: krb5_cksumtype) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_c_is_coll_proof_cksum(ctype: krb5_cksumtype) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_c_is_keyed_cksum(ctype: krb5_cksumtype) -> krb5_boolean;
}

/// [in] ignored
pub const KRB5_CRYPTO_TYPE_EMPTY: krb5_cryptotype = 0;
/// [out] header
pub const KRB5_CRYPTO_TYPE_HEADER: krb5_cryptotype = 1;
/// [in, out] plaintext
pub const KRB5_CRYPTO_TYPE_DATA: krb5_cryptotype = 2;
/// [in] associated data
pub const KRB5_CRYPTO_TYPE_SIGN_ONLY: krb5_cryptotype = 3;
/// [out] padding
pub const KRB5_CRYPTO_TYPE_PADDING: krb5_cryptotype = 4;
/// [out] checksum for encrypt
pub const KRB5_CRYPTO_TYPE_TRAILER: krb5_cryptotype = 5;
/// [out] checksum for MIC
pub const KRB5_CRYPTO_TYPE_CHECKSUM: krb5_cryptotype = 6;
/// [in] entire message without decomposing the strucutre into
/// header, data and trailer buffers
pub const KRB5_CRYPTO_TYPE_STREAM: krb5_cryptotype = 7;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_c_make_checksum_iov(context: krb5_context,
                                    cksumtype: krb5_cksumtype,
                                    key: *const krb5_keyblock,
                                    usage: krb5_keyusage,
                                    data: *mut krb5_crypto_iov,
                                    num_data: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_verify_checksum_iov(context: krb5_context,
                                      cksumtype: krb5_cksumtype,
                                      key: *const krb5_keyblock,
                                      usage: krb5_keyusage,
                                      data: *const krb5_crypto_iov,
                                      num_data: usize,
                                      valid: *mut krb5_boolean) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_encrypt_iov(context: krb5_context,
                              keyblock: *const krb5_keyblock,
                              usage: krb5_keyusage,
                              cipher_state: *const krb5_data,
                              data: *mut krb5_crypto_iov,
                              num_data: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_decypt_iov(context: krb5_context,
                             keyblock: *const krb5_keyblock,
                             usage: krb5_keyusage,
                             cipher_state: *const krb5_data,
                             data: *mut krb5_crypto_iov,
                             num_data: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_crypto_length(context: krb5_context,
                                enctype: krb5_enctype,
                                type_: krb5_cryptotype,
                                size: *mut c_uint) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_crypto_length_iov(context: krb5_context,
                                    enctype: krb5_enctype,
                                    data: *mut krb5_crypto_iov,
                                    num_data: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_c_padding_length(context: krb5_context,
                                 enctype: krb5_enctype,
                                 data_length: usize,
                                 size: *mut c_uint) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_create_key(context: krb5_context,
                             key_data: *const krb5_keyblock,
                             out: *mut krb5_key) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_reference_key(context: krb5_context,
                                key: krb5_key);
    // TODO: Doc
    pub fn krb5_k_key_keyblock(context: krb5_context,
                               key: krb5_key,
                               key_data: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_key_enctype(context: krb5_context,
                              key: krb5_key) -> krb5_enctype;
    // TODO: Doc
    pub fn krb5_k_encrypt(context: krb5_context,
                          key: krb5_key,
                          usage: krb5_keyusage,
                          cipher_state: *const krb5_data,
                          input: *const krb5_data,
                          output: *mut krb5_enc_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_encrypt_iov(context: krb5_context,
                              key: krb5_key,
                              usage: krb5_keyusage,
                              cipher_state: *const krb5_data,
                              data: *mut krb5_crypto_iov,
                              num_data: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_decrypt(context: krb5_context,
                          key: krb5_key,
                          usage: krb5_keyusage,
                          cipher_state: *const krb5_data,
                          input: *const krb5_enc_data,
                          output: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_decrypt_iov(context: krb5_context,
                              key: krb5_key,
                              usage: krb5_keyusage,
                              cipher_state: *const krb5_data,
                              data: *mut krb5_crypto_iov,
                              num_data: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_make_checksum(context: krb5_context,
                                cksumtype: krb5_cksumtype,
                                key: krb5_key,
                                usage: krb5_keyusage,
                                input: *const krb5_data,
                                cksum: *mut krb5_checksum) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_make_checksum_iov(context: krb5_context,
                                    cksumtype: krb5_cksumtype,
                                    key: krb5_key,
                                    usage: krb5_keyusage,
                                    data: *mut krb5_crypto_iov,
                                    num_data: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_verify_checksum(context: krb5_context,
                                  key: krb5_key,
                                  usage: krb5_keyusage,
                                  data: *const krb5_data,
                                  cksum: *const krb5_checksum,
                                  valid: *mut krb5_boolean) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_verify_checksum_iov(context: krb5_context,
                                      cksumtype: krb5_cksumtype,
                                      key: krb5_key,
                                      usage: krb5_keyusage,
                                      data: *const krb5_crypto_iov,
                                      num_data: usize,
                                      valid: *mut krb5_boolean) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_k_prf(context: krb5_context,
                      key: krb5_key,
                      input: *mut krb5_data,
                      output: *mut krb5_data) -> krb5_error_code;
    //ifdef KRB5_OLD_CRYPTO
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_encrypt(context: krb5_context,
                        inptr: krb5_const_pointer,
                        outptr: krb5_pointer,
                        size: usize,
                        eblock: *mut krb5_encrypt_block,
                        ivec: krb5_pointer) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_decrypt(context: krb5_context,
                        inptr: krb5_const_pointer,
                        outpt: krb5_pointer,
                        size: usize,
                        eblock: *mut krb5_encrypt_block,
                        ivec: krb5_pointer) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_process_key(context: krb5_context,
                            eblock: *mut krb5_encrypt_block,
                            key: *const krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_finish_key(context: krb5_context,
                           eblock: *mut krb5_encrypt_block) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_string_to_key(context: krb5_context,
                              eblock: *const krb5_encrypt_block,
                              keyblock: *mut krb5_keyblock,
                              data: *const krb5_data,
                              salt: *const krb5_data) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_init_random_key(context: krb5_context,
                                eblock: *const krb5_encrypt_block,
                                keyblock: *const krb5_keyblock,
                                ptr: *mut krb5_pointer) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_finish_random_key(context: krb5_context,
                                  eblock: *const krb5_encrypt_block,
                                  ptr: *mut krb5_pointer) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_random_key(context: krb5_context,
                           eblock: *const krb5_encrypt_block,
                           ptr: krb5_pointer,
                           keyblock: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_eblock_enctype(context: krb5_context,
                               eblock: *const krb5_encrypt_block) -> krb5_enctype;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_use_enctype(context: krb5_context,
                            eblock: *mut krb5_encrypt_block,
                            enctype: krb5_enctype) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "Replaced by krb5_c_* API family.")]
    pub fn krb5_encrypt_size(length: usize, crypto: krb5_enctype) -> usize;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "See `krb5_c_checksum_length()`")]
    pub fn krb5_checksum_size(context: krb5_context, ctype: krb5_cksumtype) -> usize;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "See `krb5_c_make_chekcsum()`")]
    pub fn krb5_calculate_checksum(context: krb5_context,
                                   ctype: krb5_cksumtype,
                                   in_: krb5_const_pointer,
                                   in_length: usize,
                                   seed: krb5_const_pointer,
                                   seed_length: usize,
                                   outcksum: *mut krb5_checksum) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_old_crypto")]
    #[deprecated(note = "See `krb5_c_verify_checksum()`")]
    pub fn krb5_verify_checksum(context: krb5_context,
                                ctype: krb5_cksumtype,
                                cksum: *const krb5_checksum,
                                in_: krb5_const_pointer,
                                in_length: usize,
                                seed: krb5_const_pointer,
                                seed_length: usize) -> krb5_error_code;
    // endif KRB5_OLD_CRYPTO
}

pub const KDC_OPT_FORWARDABLE: krb5_flags             = 0x40000000;
pub const KDC_OPT_FORWARDED: krb5_flags               = 0x20000000;
pub const KDC_OPT_PROXIABLE: krb5_flags               = 0x10000000;
pub const KDC_OPT_PROXY: krb5_flags                   = 0x08000000;
pub const KDC_OPT_ALLOW_POSTDATED: krb5_flags         = 0x04000000;
pub const KDC_OPT_POSTDATED: krb5_flags               = 0x02000000;

pub const KDC_OPT_RENEWABLE: krb5_flags               = 0x00800000;

pub const KDC_OPT_CNAME_IN_ADDL_TKT: krb5_flags       = 0x00020000;
pub const KDC_OPT_CANONICALIZE: krb5_flags            = 0x00010000;
pub const KDC_OPT_REQUEST_ANONYMOUS: krb5_flags       = 0x00008000;

pub const KDC_OPT_DISABLE_TRANSITED_CHEDK: krb5_flags = 0x00000020;
pub const KDC_OPT_RENEWABLE_OK: krb5_flags            = 0x00000010;
pub const KDC_OPT_ENC_TKT_IN_SKEY: krb5_flags         = 0x00000008;

pub const KDC_OPT_RENEW: krb5_flags                   = 0x00000002;
pub const KDC_OPT_VALIDATE: krb5_flags                = 0x00000001;

pub const KDC_TKT_COMMON_MASK: krb5_flags             = 0x54800000;

pub const AP_OPTS_RESERVERD: krb5_flags               = 0x80000000;
/// Use session key
pub const AP_OPTS_USE_SESSION_KEY: krb5_flags         = 0x40000000;
/// Perform a mutual authentiction exchange
pub const AP_OPTS_MUTUAL_REQUIRED: krb5_flags         = 0x20000000;

pub const AP_OPTS_ETYPE_NEGOTIATION: krb5_flags       = 0x00000002;
/// Generate a subsession key from the curretn session key obtained from
/// the credentials
pub const AP_OPTS_USE_SUBKEY: krb5_flags              = 0x00000001;

pub const AP_OPTS_WIRE_MASK: krb5_flags               = 0xfffffff0;

pub const AD_TYPE_RESERVED: u16                = 0x8000;
pub const AD_TYPE_EXTERNAL: u16                = 0x4000;
pub const AD_TYPE_REGISTERED: u16              = 0x2000;

pub const AD_TYPE_FIELD_TYPE_MASK: u16         = 0x1fff;

pub const TKT_FLG_FORWARDABLE: krb5_flags             = 0x40000000;
pub const TKT_FLG_FORWARDED: krb5_flags               = 0x20000000;
pub const TKT_FLG_PROXIABLE: krb5_flags               = 0x10000000;
pub const TKT_FLG_PROXY: krb5_flags                   = 0x08000000;
pub const TKT_FLG_MAY_POSTDATE: krb5_flags            = 0x04000000;
pub const TKT_FLG_POSTDATED: krb5_flags               = 0x02000000;
pub const TKT_FLG_INVALID: krb5_flags                 = 0x01000000;
pub const TKT_FLG_RENEWABLE: krb5_flags               = 0x00800000;
pub const TKT_FLG_INITIAL: krb5_flags                 = 0x00400000;
pub const TKT_FLG_PRE_AUTH: krb5_flags                = 0x00200000;
pub const TKT_FLG_HW_AUTH: krb5_flags                 = 0x00100000;
pub const TKT_FLG_TRANSIT_POLICY_CHECKED: krb5_flags  = 0x00080000;
pub const TKT_FLG_OK_AS_DELEGATE: krb5_flags          = 0x00040000;
pub const TKT_FLG_ENC_PA_REP: krb5_flags              = 0x00010000;
pub const TKT_FLG_ANONYMOUS: krb5_flags               = 0x00008000;

pub const LR_TYPE_THIS_SERVER_ONLY: u16        = 0x8000;
pub const LR_TYPE_INTERPRETATION_MASK: u16     = 0x7fff;

pub const MSEC_DIRBIT: u16                     = 0x8000;
pub const MSEC_VAL_MASK: u16                   = 0x7fff;

pub const KRB5_PVNO: usize = 4;

/// Initial authentication request
pub const KRB5_AS_REQ: krb5_msgtype = 10;
/// Response to AS requset
pub const KRB5_AS_REP: krb5_msgtype = 11;
/// Ticket granting server request
pub const KRB5_TGS_REQ: krb5_msgtype = 12;
/// Response to TGS request
pub const KRB5_TGS_REP: krb5_msgtype = 13;
/// Auth req to application server
pub const KRB5_AP_REQ: krb5_msgtype = 14;
/// Repsonse to mutual AP request
pub const KRB5_AP_REP: krb5_msgtype = 15;
/// Safe application message
pub const KRB5_SAFE: krb5_msgtype = 20;
/// Private application message
pub const KRB5_PRIV: krb5_msgtype = 21;
/// Cred forwarding message
pub const KRB5_CRED: krb5_msgtype = 22;
/// Error response
pub const KRB5_ERROR: krb5_msgtype = 30;

// TODO: Find the proper type for these
pub const KRB5_LRQ_NONE: isize = 0;
pub const KRB5_LRQ_ALL_LAST_TGT: isize = 1;
pub const KRB5_LRQ_ONE_LAST_TGT: isize = -1;
pub const KRB5_LRQ_ALL_LAST_INITIAL: isize = 2;
pub const KRB5_LRQ_ONE_LAST_INITIAL: isize = -2;
pub const KRB5_LRQ_ALL_LAST_TGT_ISSUED: isize = 3;
pub const KRB5_LRQ_ONE_LAST_TGT_ISSUED: isize = -3;
pub const KRB5_LRQ_ALL_LAST_RENEWAL: isize = 4;
pub const KRB5_LRQ_ONE_LAST_RENEWAL: isize = -4;
pub const KRB5_LRQ_ALL_LAST_REQ: isize = 5;
pub const KRB5_LRQ_ONE_LAST_REQ: isize = -5;
pub const KRB5_LRQ_ALL_PW_EXPTIME: isize = 6;
pub const KRB5_LRQ_ONE_PW_EXPTIME: isize = -6;
pub const KRB5_LRQ_ALL_ACCT_EXPTIME: isize = 7;
pub const KRB5_LRQ_ONE_ACCT_EXPTIME: isize = -7;

pub const KRB5_PADATA_NONE: isize = 0;
pub const KRB5_PADATA_AP_REQ: isize = 1;
pub const KRB5_PADATA_TGS_REQ: isize = KRB5_PADATA_AP_REQ;
/// RFC 4120
pub const KRB5_PADATA_ENC_TIMESTAMP: isize = 2;
/// RFC 4120
pub const KRB5_PADATA_PW_SALT: isize = 3;
/// Not used, key encrypted within self
pub const KRB5_PADATA_ENC_ENCKEY: isize = 4;
/// timestamp encrytped in key, RFC 4120
pub const KRB5_PADATA_ENC_UNIX_TIME: isize = 5;
/// SecurId passcode. RFC 4120
pub const KRB5_PADATA_ENC_SANDIA_SECURID: isize = 6;
/// Sesame project. RFC 4120
pub const KRB5_PADATA_SESAME: isize = 7;
/// OSF DCE. RFC 4120
pub const KRB5_PADATA_OSF_DCE: isize = 8;
/// Cybersafe, RFC 4120
pub const KRB5_CYBERSAFE_SECUREID: isize = 9;
/// Cygnus, RFC 4120, 3961
pub const KRB5_PADATA_AFS3_SALT: isize = 10;
/// Etype info for preauth. RFC 4120
pub const KRB5_PADATA_ETYPE_INFO: isize = 11;
/// SAM/OTP
pub const KRB5_PADATA_SAM_CHALLENGE: isize = 12;
/// SAM/OTP
pub const KRB5_PADATA_SAM_RESPONSE: isize = 13;
/// PKINIT
pub const KRB5_PADATA_PK_AS_REQ_OLD: isize = 14;
/// PKINIT
pub const KRB5_PADATA_PK_AS_REP_OLD: isize = 15;
/// PKINIT. RFC 4556
pub const KRB5_PADATA_PK_AS_REQ: isize = 16;
/// PKINIT. RFC 4556
pub const KRB5_PADATA_PK_AS_REP: isize = 17;
/// RFC 4120
pub const KRB5_PADATA_ETYPE_INFO2: isize = 19;
/// RFC 4120
pub const KRB5_PADATA_USE_SEPCIFIED_KVNO: isize = 20;
/// Windows 2000 referrals. RFC 6820
pub const KRB5_PADATA_SVR_REFERRAL_INFO: isize = 20;
/// SAM/OTP. RFC 4120
pub const KRB5_PADATA_SAM_REDIRECT: isize = 21;
/// Embedded in typed data. RFC 4120
pub const KRB5_PADATA_GET_FROM_TYPED_DATA: isize = 22;
/// Draft challenge system
pub const KRB5_PADATA_REFERRAL: isize = 25;
/// draft challenge system, updated
pub const KRB5_PADATA_SAM_CHALLENGE_2: isize = 30;
/// draft challenge system, updated
pub const KRB5_PADATA_SAM_RESPONSE_2: isize = 31;
/// include Windows PAC
pub const KRB5_PADATA_PAC_REQUEST: isize = 128;
/// username protocol transition request
pub const KRB5_PADATA_FOR_USER: isize = 129;
/// certificate protocol transition request
pub const KRB5_PADATA_S4U_X509_USER: isize = 130;
/// AS checksum
pub const KRB5_PADATA_AS_CHECKSUM: isize = 132;
/// RFC 6113
pub const KRB5_PADATA_FX_COOKIE: isize = 133;
/// RFC 6113
pub const KRB5_PADATA_FX_FAST: isize = 136;
/// RFC 6113
pub const KRB5_PADATA_FX_ERROR: isize = 137;
/// RFC 6113
pub const KRB5_PADATA_ENCRYPTED_CHALLENGE: isize = 138;
/// RFC 6560 section 4.1
pub const KRB5_PADATA_OTP_CHALLENGE: isize = 141;
/// RFC 6560 section 4.2
pub const KRB5_PADATA_OTP_REQUEST: isize = 142;
/// RFC 6560 section 4.3
pub const KRB5_PADATA_OTP_PIN_CHANGE: isize = 144;
/// RFC 6112
pub const KRB5_PADATA_PKINIT_KX: isize = 147;
/// RFC 6806
pub const KRB5_ENCPADATA_REQ_ENC_PA_REP: isize = 149;

pub const KRB5_SAM_USE_SAD_AS_KEY: isize = 0x80000000;
pub const KRB5_SAM_SEND_ENCRYPTED_SAD: isize = 0x40000000;
/// currently must be zero
pub const KRB5_SAM_MUST_PK_ENCRYPT_SAD: isize = 0x20000000;

/// Transited encoding types
pub const KRB5_DOMAIN_X500_COMPRESS: isize = 1;
/// alternate authentication types
pub const KRB5_ALTAUTH_ATT_CHALLENGE_RESPONSE: isize = 64;

pub const KBR5_AUTHDATA_IF_RELEVANT: krb5_authdatatype = 1;
pub const KRB5_AUTHDATA_KDC_ISSUED: krb5_authdatatype = 4;
pub const KRB5_AUTHDATA_AND_OR: krb5_authdatatype = 5;
pub const KRB5_AUTHDATA_MANDATORY_FOR_KDC: krb5_authdatatype = 8;
pub const KRB5_AUTHDATA_INITIAL_VERIFIED_CAS: krb5_authdatatype = 9;
pub const KRB5_AUTHDATA_OSF_DC: krb5_authdatatype = 64;
pub const KRB5_AUTHDATA_SESAME: krb5_authdatatype = 65;
pub const KRB5_AUTHDATA_WIN2K_PAC: krb5_authdatatype = 128;
/// RFC 4537
pub const KRB5_AUTHDATA_ETYPE_NEGOTIATION: krb5_authdatatype = 129;
/// formerly 142 in krb5 1.8
pub const KRB5_AUTHDATA_SIGNTICKET: krb5_authdatatype = 512;
pub const KRB5_AUTHDATA_FX_ARMOR: krb5_authdatatype = 71;

// TODO: find the proper type for these
/// Success
pub const KRB5_KPASSWD_SUCCESS: isize = 0;
/// Malformed request
pub const KRB5_KPASSWD_MALFORMED: isize = 1;
/// Server error
pub const KRB5_KPASSWD_HARDERROR: isize = 2;
/// Authentication error
pub const KRB5_KPASSWD_AUTHERROR: isize = 3;
/// Password change rejected
pub const KRB5_KPASSWD_SOFTERROR: isize = 4;
/// Not authorized
pub const KRB5_KPASSWD_ACCESSDENIED: isize = 5;
/// Unknown RPC version
pub const KRB5_KPASSWD_BAD_VERSION: isize = 6;
/// The presented credentials were not obtained using a password directly
pub const KRB5_KPASSWD_INITIAL_FLAG_NEEDED: isize = 7;

// TODO: Docs
#[repr(C)]
pub struct krb5_ticket_times {
    pub authtime: krb5_timestamp,
    pub starttime: krb5_timestamp,
    pub endtime: krb5_timestamp,
    pub renew_till: krb5_timestamp,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_authdata {
    pub magic: krb5_magic,
    pub ad_type: krb5_authdatatype,
    pub length: c_uint,
    pub contents: *mut krb5_octet,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_transited {
    pub magic: krb5_magic,
    pub tr_type: krb5_octet,
    pub tr_contents: krb5_data,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_enc_tkt_part {
    pub magic: krb5_magic,
    pub flags: krb5_flags,
    pub session: *mut krb5_keyblock,
    pub client: krb5_principal,
    pub transited: krb5_transited,
    pub times: krb5_ticket_times,
    pub caddrs: *mut *mut krb5_address,
    pub authorization_data: *mut *mut krb5_authdata,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_ticket {
    pub magic: krb5_magic,
    pub server: krb5_principal,
    pub enc_part: krb5_enc_data,
    pub enc_part2: *mut krb5_enc_tkt_part,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_authenticator {
    pub magic: krb5_magic,
    pub client: krb5_principal,
    pub checksum: *mut krb5_checksum,
    pub cusec: krb5_int32,
    pub ctime: krb5_timestamp,
    pub subkey: *mut krb5_keyblock,
    pub seq_number: krb5_ui_4,
    pub authorization_data: *mut *mut krb5_authdata,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_tkt_authent {
    pub magic: krb5_magic,
    pub ticket: *mut krb5_ticket,
    pub authenticator: *mut krb5_authenticator,
    pub ap_options: krb5_flags,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_creds {
    pub magic: krb5_magic,
    pub client: krb5_principal,
    pub server: krb5_principal,
    pub keyblock: krb5_keyblock,
    pub times: krb5_ticket_times,
    pub is_skey: krb5_boolean,
    pub ticket_flags: krb5_flags,
    pub addresses: *mut *mut krb5_address,
    pub ticket: krb5_data,
    pub second_ticket: krb5_data,
    pub authdata: *mut *mut krb5_authdata,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_last_req_entry {
    pub magic: krb5_magic,
    pub lr_type: krb5_int32,
    pub value: krb5_timestamp,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_pa_data {
    pub magic: krb5_magic,
    pub pa_type: krb5_preauthtype,
    pub length: c_uint,
    pub contents: *mut krb5_octet,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_typed_data {
    pub magic: krb5_magic,
    pub type_: krb5_int32,
    pub length: c_uint,
    pub data: *mut krb5_octet,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_kdc_req {
    pub magic: krb5_magic,
    pub msg_type: krb5_msgtype,
    pub padata: *mut *mut krb5_pa_data,
    pub kdc_options: krb5_flags,
    pub client: krb5_principal,
    pub server: krb5_principal,
    pub from: krb5_timestamp,
    pub till: krb5_timestamp,
    pub rtime: krb5_timestamp,
    pub nonce: krb5_int32,
    pub nktypes: c_int,
    pub ktype: *mut krb5_enctype,
    pub addressses: *mut *mut krb5_address,
    pub authorization_data: krb5_enc_data,
    pub unenc_authdata: *mut *mut krb5_authdata,
    pub second_ticket: *mut *mut krb5_ticket,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_enc_kdc_rep_part {
    pub magic: krb5_magic,
    pub msg_type: krb5_msgtype,
    pub session: *mut krb5_keyblock,
    pub last_req: *mut *mut krb5_last_req_entry,
    pub nonce: krb5_int32,
    pub key_exp: krb5_timestamp,
    pub flags: krb5_flags,
    pub times: krb5_ticket_times,
    pub server: krb5_principal,
    pub caddrs: *mut *mut krb5_address,
    pub enc_padata: *mut *mut krb5_pa_data,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_kdc_rep {
    pub magic: krb5_magic,
    pub msg_type: krb5_msgtype,
    pub padata: *mut *mut krb5_pa_data,
    pub client: krb5_principal,
    pub ticket: *mut krb5_ticket,
    pub enc_part: krb5_enc_data,
    pub enc_part2: *mut krb5_enc_kdc_rep_part,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_error {
    pub magic: krb5_magic,
    pub ctime: krb5_timestamp,
    pub cusec: krb5_int32,
    pub susec: krb5_int32,
    pub stime: krb5_timestamp,
    pub error: krb5_ui_4,
    pub client: krb5_principal,
    pub server: krb5_principal,
    pub text: krb5_data,
    pub e_data: krb5_data,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_ap_req {
    pub magic: krb5_magic,
    pub ap_options: krb5_flags,
    pub ticket: *mut krb5_ticket,
    pub authenticator: krb5_enc_data,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_ap_rep {
    pub magic: krb5_magic,
    pub enc_part: krb5_enc_data,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_ap_rep_enc_part {
    pub magic: krb5_magic,
    pub ctime: krb5_timestamp,
    pub cusec: krb5_int32,
    pub subkey: *mut krb5_keyblock,
    pub seq_number: krb5_ui_4,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_response {
    pub magic: krb5_magic,
    pub message_type: krb5_octet,
    pub response: krb5_data,
    pub expected_nonce: krb5_int32,
    pub request_time: krb5_timestamp,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_cred_info {
    pub magic: krb5_magic,
    pub session: *mut krb5_keyblock,
    pub client: krb5_principal,
    pub server: krb5_principal,
    pub flags: krb5_flags,
    pub times: krb5_ticket_times,
    pub caddrs: *mut *mut krb5_address,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_cred_enc_part {
    pub magic: krb5_magic,
    pub nonce: krb5_int32,
    pub timestamp: krb5_timestamp,
    pub usec: krb5_int32,
    pub s_address: *mut krb5_address,
    pub r_address: *mut krb5_address,
    pub ticket_info: *mut *mut krb5_cred_info,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_cred {
    pub magic: krb5_magic,
    pub tickets: *mut *mut krb5_ticket,
    pub enc_part: krb5_enc_data,
    pub enc_part2: *mut krb5_cred_enc_part,
}

// TODO: Docs
#[repr(C)]
pub struct passwd_phrase_element {
    pub magic: krb5_magic,
    pub passwd: *mut krb5_data,
    pub phrase: *mut krb5_data,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_pwd_data {
    pub magic: krb5_magic,
    pub sequence_count: c_int,
    pub element: *mut *mut passwd_phrase_element,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_pa_svr_referral_data {
    pub principal: krb5_principal,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_pa_server_referral_data {
    pub referred_realm: *mut krb5_data,
    pub true_principal_name: krb5_principal,
    pub requested_principal_name: krb5_principal,
    pub referral_valid_until: krb5_timestamp,
    pub rep_cksum: krb5_checksum,
}

// TODO: Docs
#[repr(C)]
pub struct krb5_pa_pac_req {
    pub include_pac: krb5_boolean,
}

// krb5/krb5.h:2151
// TODO: Find the proper datatypes
/// Prevent replays with timestamps and replay cache
pub const KRB5_AUTH_CONTEXT_DO_TIME: krb5_flags      = 0x00000001;
/// Save timestamps for application
pub const KRB5_AUTH_CONTEXT_RET_TIME: krb5_flags     = 0x00000002;
/// Prevent replays with sequence numbers
pub const KRB5_AUTH_CONTEXT_DO_SEQUENCE: krb5_flags  = 0x00000004;
/// Save sequence numbers for application
pub const KRB5_AUTH_CONTEXT_RET_SEQUENCE: krb5_flags = 0x00000008;
pub const KRB5_AUTH_CONTEXT_PERMIT_ALL: krb5_flags   = 0x00000010;
pub const KRB5_AUTH_CONTEXT_USE_SUBKEY: krb5_flags   = 0x00000020;

// TODO: Docs
#[repr(C)]
pub struct krb5_replay_data {
    pub timestamp: krb5_timestamp,
    pub usec: krb5_int32,
    pub seq: krb5_ui_4,
}

/// Generate the local network address
pub const KRB5_AUTH_CONTEXT_GENERATE_LOCAL_ADDR: krb5_flags       = 0x00000001;
/// Generate the remote network address
pub const KRB5_AUTH_CONTEXT_GENERATE_REMOTE_ADDR: krb5_flags      = 0x00000002;
/// Generate the local network address and the local port
pub const KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR: krb5_flags  = 0x00000004;
/// Generate the remote network address and the remote port
pub const KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR: krb5_flags = 0x00000008;

pub type krb5_mk_req_checksum_func = extern "C" fn(krb5_context, krb5_auth_context, *mut c_void, *mut *mut krb5_data) -> krb5_error_code;

pub type krb5_cc_cursor = krb5_pointer;

pub enum _krb5_ccache {}
pub type krb5_ccache = *mut _krb5_ccache;
pub enum _krb5_cc_ops {}
pub type krb5_cc_ops = *mut _krb5_cc_ops;
pub enum _krb5_cccol_cursor {}
pub type krb5_cccol_cursor = *mut _krb5_cccol_cursor;

/// The requested lifetime must be at least as great as the time specified.
pub const KRB5_TC_MATCH_TIMES: krb5_flags        = 0x00000001;
/// The is_skey field must match exactly
pub const KRB5_TC_MATCH_IS_KEY: krb5_flags       = 0x00000002;
/// All the flags set in the match credentials must be set
pub const KRB5_TC_MATCH_FLAGS: krb5_flags        = 0x00000004;
/// All the time fields must match exactly
pub const KRB5_TC_MATCH_TIMES_EXACT: krb5_flags  = 0x00000008;
/// All the flags must match exactly
pub const KRB5_TC_MATCH_FLAGS_EXACT: krb5_flags  = 0x00000010;
/// The authorization data must match
pub const KRB5_TC_MATCH_AUTHDATA: krb5_flags     = 0x00000020;
/// Only the name portion of the principal name must match
pub const KRB5_TC_MATCH_SRV_NAMEONLY: krb5_flags = 0x00000040;
/// The second ticket must match
pub const KRB5_TC_MATCH_2ND_TKT: krb5_flags      = 0x00000080;
/// The encryption key type must match
pub const KRB5_TC_MATCH_KTYPE: krb5_flags        = 0x00000100;
/// The supported key types must match
pub const KRB5_TC_SUPPORTED_KTYPES: krb5_flags   = 0x00000200;

/// Open and close the file for each cache operation
pub const KRB5_TC_OPENCLOSE: krb5_flags = 0x00000001;
pub const KRB5_TC_NOTICKKET: krb5_flags = 0x00000002;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_cc_get_name(context: krb5_context,
                            cache: krb5_ccache) -> *const c_char;
    // TODO: Doc
    pub fn krb5_cc_get_full_name(context: krb5_context,
                                 cache: krb5_ccache,
                                 fullname_out: *mut *mut c_char) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_deprecated")]
    pub fn krb5_cc_gen_new(context: krb5_context,
                           cache: *mut krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_initialize(context: krb5_context,
                              cache: krb5_ccache,
                              principal: krb5_principal) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_destroy(context: krb5_context,
                           cache: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_close(context: krb5_context,
                         cache: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_store_cred(context: krb5_context,
                              cache: krb5_ccache,
                              creds: *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_retrieve_cred(context: krb5_context,
                                 cache: krb5_ccache,
                                 flags: krb5_flags,
                                 mcreds: *mut krb5_creds,
                                 creds: *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_get_principal(context: krb5_context,
                                 cache: krb5_ccache,
                                 principal: *mut krb5_principal) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_start_seq_get(context: krb5_context,
                                 cache: krb5_ccache,
                                 cursor: *mut krb5_cc_cursor) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_next_cred(context: krb5_context,
                             cache: krb5_ccache,
                             cursor: *mut krb5_cc_cursor,
                             creds: *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_end_seq_get(context: krb5_context,
                               cache: krb5_ccache,
                               cursor: *mut krb5_cc_cursor) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_remove_cred(context: krb5_context,
                               cache: krb5_ccache,
                               flags: krb5_flags) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_set_flags(context: krb5_context,
                             cache: krb5_ccache,
                             flags: krb5_flags) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_get_flags(context: krb5_context,
                             cache: krb5_ccache,
                             flags: *mut krb5_flags) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_get_type(context: krb5_context,
                            cache: krb5_ccache) -> *const c_char;
    // TODO: Doc
    pub fn krb5_cc_move(context: krb5_context,
                        src: krb5_ccache,
                        dst: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_last_change_time(context: krb5_context,
                                    ccache: krb5_ccache,
                                    change_time: *mut krb5_timestamp) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_lock(context: krb5_context,
                        ccache: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_unlock(context: krb5_context,
                          ccache: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cccol_cursor_new(context: krb5_context,
                                 cursor: *mut krb5_cccol_cursor) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cccol_cursor_next(context: krb5_context,
                                  cursor: krb5_cccol_cursor,
                                  ccache: *mut krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cccol_cursor_free(context: krb5_context,
                                  cursor: *mut krb5_cccol_cursor) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cccol_have_content(context: krb5_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cccol_last_change_time(context: krb5_context,
                                       change_time: *mut krb5_timestamp) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cccol_lock(context: krb5_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cccol_unlock(context: krb5_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_new_unique(context: krb5_context,
                              type_: *const c_char,
                              hint: *const c_char,
                              id: *mut krb5_ccache) -> krb5_error_code;
}

pub enum krb5_rc_st {}
pub type krb5_rcache = *mut krb5_rc_st;

/// Long enough for MAXPATHLEN + some extra
pub const MAX_KEYTAB_NAME_LEN: usize = 1100;

pub type krb5_kt_cursor = krb5_pointer;

// TODO: Docs
#[repr(C)]
pub struct krb5_keytab_entry {
    pub magic: krb5_magic,
    pub principal: krb5_principal,
    pub timestamp: krb5_timestamp,
    pub vno: krb5_kvno,
    pub key: krb5_keyblock
}

pub enum _krb5_kt {}
pub type krb5_keytab = *mut _krb5_kt;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_kt_get_type(context: krb5_context,
                            keytab: krb5_keytab) -> *const c_char;
    // TODO: Doc
    pub fn krb5_kt_get_name(context: krb5_context,
                            keytab: krb5_keytab,
                            name: *mut c_char,
                            namelen: c_uint) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_close(context: krb5_context,
                         keytab: krb5_keytab) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_get_entry(context: krb5_context,
                             keytab: krb5_keytab,
                             principal: krb5_principal,
                             vno: krb5_kvno,
                             enctype: krb5_enctype,
                             entry: *mut krb5_keytab_entry) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_start_seq_get(context: krb5_context,
                                 keytab: krb5_keytab,
                                 cursor: *mut krb5_kt_cursor) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_next_entry(context: krb5_context,
                              keytab: krb5_keytab,
                              entry: *mut krb5_keytab_entry,
                              cursor: *mut krb5_kt_cursor) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_end_seq_get(context: krb5_context,
                               keytab: krb5_keytab,
                               cursor: *mut krb5_kt_cursor) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_have_content(context: krb5_context,
                                keytab: krb5_keytab) -> krb5_error_code;
}

/// Use secure context configuration
pub const KRB5_INIT_CONTEXT_SECURE: krb5_flags = 0x1;
/// Use KDC configuration if available
pub const KRB5_INIT_CONTEXT_KDC: krb5_flags = 0x2;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_init_context(context: *mut krb5_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_secure_context(context: *mut krb5_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_context_profile(profile: *mut _profile_t,
                                     flags: krb5_flags,
                                     context: krb5_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_free_context(context: krb5_context);
    // TODO: Doc
    pub fn krb5_copy_context(ctx: krb5_context,
                             nctx_out: krb5_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_set_default_tgs_enctypes(context: krb5_context,
                                         etypes: *const krb5_enctype) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_permitted_enctypes(context: krb5_context,
                                       ktypes: *mut *mut krb5_enctype) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_is_thread_safe() -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_server_decrypt_ticket_keytab(context: krb5_context,
                                             kt: krb5_keytab,
                                             ticket: *mut krb5_ticket) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_free_tgt_creds(context: krb5_context,
                               rgts: *mut *mut krb5_creds);

}

/// Want user-user ticket
pub const KRB5_GC_USER_USER: krb5_flags = 1;
/// Want cached ticket only
pub const KRB5_GC_CACHED: krb5_flags = 2;
/// Set canonicalize KDC option
pub const KRB5_GC_CANONICALIZE: krb5_flags = 4;
/// Do not store in credential cache
pub const KRB5_GC_NO_STORE: krb5_flags = 8;
/// Acquire forwardable tickets
pub const KRB5_GC_FORWARDABLE: krb5_flags = 16;
/// Disable transited check
pub const KRB5_GC_NO_TRANSIT_CHECK: krb5_flags = 32;
/// Constrained delegation
pub const KRB5_GC_CONSTRAINED_DELEGATION: krb5_flags = 64;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_get_credentials(context: krb5_context,
                                options: krb5_flags,
                                ccache: krb5_ccache,
                                in_creds: *mut krb5_creds,
                                out_creds: *mut *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_credentials_validate(context: krb5_context,
                                         options: krb5_flags,
                                         ccache: krb5_ccache,
                                         in_creds: *mut krb5_creds,
                                         out_creds: *mut *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_credentials_renew(context: krb5_context,
                                      options: krb5_flags,
                                      ccache: krb5_ccache,
                                      in_creds: *mut krb5_creds,
                                      out_creds: *mut *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_req(context: krb5_context,
                       auth_context: *mut krb5_auth_context,
                       ap_req_options: krb5_flags,
                       service: *mut c_char,
                       hostname: *mut c_char,
                       in_data: *mut krb5_data,
                       ccache: krb5_ccache,
                       outbuf: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_req_extended(context: krb5_context,
                                auth_context: *mut krb5_auth_context,
                                ap_req_options: krb5_flags,
                                in_data: *mut krb5_data,
                                in_creds: *mut krb5_creds,
                                outbuf: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_rep(context: krb5_context,
                       auth_context: krb5_auth_context,
                       outbuf: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_rep_dce(context: krb5_context,
                           auth_context: krb5_auth_context,
                           outbuf: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_rd_rep(context: krb5_context,
                       auth_context: krb5_auth_context,
                       inbuf: *const krb5_data,
                       repl: *mut *mut krb5_ap_rep_enc_part) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_rd_rep_dce(context: krb5_context,
                           auth_context: krb5_auth_context,
                           inbuf: *const krb5_data,
                           nonce: *mut krb5_ui_4) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_error(context: krb5_context,
                         dec_err: *const krb5_error,
                         enc_err: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_rd_error(context: krb5_context,
                         enc_errbuf: *const krb5_data,
                         dec_error: *mut *mut krb5_error) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_rd_safe(context: krb5_context,
                        auth_context: krb5_auth_context,
                        inbuf: *const krb5_data,
                        outbuf: *mut krb5_data,
                        outdata: *mut krb5_replay_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_rd_priv(context: krb5_context,
                        auth_context: krb5_auth_context,
                        inbuf: *const krb5_data,
                        outbuf: *mut krb5_data,
                        outdata: *mut krb5_replay_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_parse_name(context: krb5_context,
                           name: *const c_char,
                           principal_out: *mut krb5_principal) -> krb5_error_code;
}

/// Error if realm is present
pub const KRB5_PRINCIPAL_PARSE_NO_REALM: krb5_flags = 0x1;
/// Error if realm is not present
pub const KRB5_PRINCIPAL_PARSE_REQUIRE_REALM: krb5_flags = 0x2;
/// Create singe-component enterprise principle
pub const KRB5_PRINCIPAL_PARSE_ENTERPRSIE: krb5_flags = 0x4;
/// Ignore realm if present
pub const KRB5_PRINCIPAL_PARSE_IGNORE_REALM: krb5_flags = 0x8;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_parse_name_flags(context: krb5_context,
                                 name: *const c_char,
                                 flags: krb5_flags,
                                 principal_out: *mut krb5_principal) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_unparse_name(context: krb5_context,
                             principal: krb5_const_principal,
                             name: *mut *mut c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_unparse_name_ext(context: krb5_context,
                                 principal: krb5_const_principal,
                                 name: *mut *mut c_char,
                                 size: *mut c_uint) -> krb5_error_code;
}

/// Omit realm if it is the local realm
pub const KRB5_PRINCIPAL_UNPARSE_SHORT: krb5_flags = 0x1;
/// Omit realm always
pub const KRB5_PRINCIPAL_UNPARSE_NO_REALM: krb5_flags = 0x2;
/// Don't escape special characters
pub const KRB5_PRINCIPAL_UNPARSE_DISPLAY: krb5_flags = 0x4;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_unparse_name_flags(context: krb5_context,
                                   principal: krb5_const_principal,
                                   flags: krb5_flags,
                                   name: *mut *mut c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_unparse_name_flags_ext(context: krb5_context,
                                       principal: krb5_const_principal,
                                       flags: krb5_flags,
                                       name: *mut *mut c_char,
                                       size: c_uint) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_set_principal_realm(context: krb5_context,
                                    principal: krb5_principal,
                                    realm: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_address_search(context: krb5_context,
                               addr: *const krb5_address,
                               addrlist: *mut krb5_address) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_address_compare(context: krb5_context,
                                addr1: *const krb5_address,
                                addr2: *const krb5_address) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_address_order(context: krb5_context,
                              addr1: *const krb5_address,
                              addr2: *const krb5_address) -> c_int;
    // TODO: Doc
    pub fn krb5_realm_compare(context: krb5_context,
                              princ1: krb5_const_principal,
                              princ2: krb5_const_principal) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_principal_compare(context: krb5_context,
                                  princ1: krb5_const_principal,
                                  princ2: krb5_const_principal) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_principal_compare_any_realm(context: krb5_context,
                                            princ1: krb5_const_principal,
                                            princ2: krb5_const_principal) -> krb5_boolean;
}

// TODO: Doc
pub const KRB5_PRINCIPAL_COMPARE_INGORE_REALM: krb5_flags = 1;
// TODO: Doc
pub const KRB5_PRINCIPAL_COMPARE_ENTERPRSIE: krb5_flags = 2;
// TODO: Doc
pub const KRB5_PRINCIPAL_COMPARE_CASEFOLD: krb5_flags = 4;
// TODO: Doc
pub const KRB5_PRINCIPAL_COMPARE_UTF8: krb5_flags = 8;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_principal_compare_flags(context: krb5_context,
                                        princ1: krb5_const_principal,
                                        princ2: krb5_const_principal,
                                        flags: krb5_flags) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_init_keyblock(context: krb5_context,
                              enctype: krb5_enctype,
                              length: usize,
                              out: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_keyblock(context: krb5_context,
                              from: *const krb5_keyblock,
                              to: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_keyblock_contents(context: krb5_context,
                                       from: *const krb5_keyblock,
                                       to: *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_creds(context: krb5_context,
                           incred: *const krb5_creds,
                           outcred: *mut *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_data(context: krb5_context,
                          indata: *const krb5_data,
                          outdata: *mut *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_principal(context: krb5_context,
                               inprinc: krb5_const_principal,
                               outprinc: *mut krb5_principal) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_addresses(context: krb5_context,
                               inaddr: *mut *const krb5_address,
                               outaddr: *mut *mut krb5_address) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_ticket(context: krb5_context,
                            from: *const krb5_ticket,
                            pto: *mut *mut krb5_ticket) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_authdata(context: krb5_context,
                              in_authdat: *mut *const krb5_authdata,
                              out: *mut *mut krb5_authdata) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_find_authdata(context: krb5_context,
                              ticket_authdata: *mut *const krb5_authdata,
                              ap_req_authdata: *mut *const krb5_authdata,
                              ad_type: krb5_authdatatype,
                              results: *mut *mut *mut krb5_authdata) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_merge_authdata(context: krb5_context,
                               inauthdat1: *mut *const krb5_authdata,
                               inauthdat2: *mut *const krb5_authdata,
                               outauthdat: *mut *mut *mut krb5_authdata) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_authenticator(context: krb5_context,
                                   authfrom: *const krb5_authenticator,
                                   authto: *mut *mut krb5_authenticator) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_copy_checksum(context: krb5_context,
                              ckfrom: *const krb5_checksum,
                              ckto: *mut *mut krb5_checksum) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_server_rcache(context: krb5_context,
                                  piece: *const krb5_data,
                                  rcptr: *mut krb5_rcache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_build_principal_ext(context: krb5_context,
                                    princ: *mut krb5_principal,
                                    rlen: c_uint,
                                    realm: *const c_char, ...) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_build_principal(context: krb5_context,
                                princ: *mut krb5_principal,
                                rlen: c_uint,
                                real: *const c_char, ...) -> krb5_error_code;

    // #[cfg(feature = "krb5_deprecated")]
    // TODO: Doc
    // TODO:  krb5_build_principal_va

    // TODO: Doc
    // TODO: pub fn krb5_build_principal_alloc_va

    // TODO: Doc
    pub fn krb5_425_conv_principal(context: krb5_context,
                                   name: *const c_char,
                                   instance: *const c_char,
                                   realm: *const c_char,
                                   princ: *mut krb5_principal) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_524_conv_principal(context: krb5_context,
                                   princ: krb5_const_principal,
                                   name: *mut c_char,
                                   inst: *mut c_char,
                                   realm: *mut c_char) -> krb5_error_code;
}

#[deprecated]
pub enum credentials {}

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    #[allow(deprecated)]
    pub fn krb5_524_convert_creds(context: krb5_context,
                                  v5creds: *mut krb5_creds,
                                  v4creds: *mut credentials) -> c_int;

    // TODO: krb524_init_ets

    // TODO: Doc
    pub fn krb5_kt_resolve(context: krb5_context,
                           name: *const c_char,
                           ktid: *mut krb5_keytab) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_dup(context: krb5_context,
                       in_: krb5_keytab,
                       out: *mut krb5_keytab) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_default_name(context: krb5_context,
                                name: *mut c_char,
                                name_size: c_int) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_default(context: krb5_context,
                           id: *mut krb5_keytab) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_client_default(context: krb5_context,
                                  keytab_out: *mut krb5_keytab) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_free_keytab_entry_contents(context: krb5_context,
                                           entry: *mut krb5_keytab_entry) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_free_entry(context: krb5_context,
                              entry: *mut krb5_keytab_entry) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_remove_entry(context: krb5_context,
                                id: krb5_keytab,
                                entry: *mut krb5_keytab_entry) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_add_entry(context: krb5_context,
                             id: krb5_keytab,
                             entry: *mut krb5_keytab_entry) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_principal2salt(context: krb5_context,
                               pr: krb5_const_principal,
                               ret: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_resolve(context: krb5_context,
                           name: *const c_char,
                           cache: *mut krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_dup(context: krb5_context,
                       in_: krb5_ccache,
                       out: *mut krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_default_name(context: krb5_context) -> *const c_char;
    // TODO: Doc
    pub fn krb5_cc_set_default_name(context: krb5_context,
                                    name: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_default(context: krb5_context,
                           ccache: *mut krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_copy_creds(context: krb5_context,
                              incc: krb5_ccache,
                              outcc: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_get_config(context: krb5_context,
                              id: krb5_ccache,
                              principal: krb5_const_principal,
                              key: *const c_char,
                              data: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_set_config(context: krb5_context,
                              id: krb5_ccache,
                              principal: krb5_const_principal,
                              key: *const c_char,
                              data: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_is_config_principal(context: krb5_context,
                                    principal: krb5_const_principal) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_cc_switch(context: krb5_context,
                          cache: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_support_switch(context: krb5_context,
                                  type_: *const c_char) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_cc_cache_match(context: krb5_context,
                               client: krb5_principal,
                               cache_out: *mut krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cc_select(context: krb5_context,
                          server: krb5_principal,
                          cache_out: *mut krb5_ccache,
                          princ_out: *mut krb5_principal) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_free_principal(context: krb5_context,
                               val: krb5_principal);
    // TODO: Doc
    pub fn krb5_free_authenticator(context: krb5_context,
                                   val: *mut krb5_authenticator);
    // TODO: Doc
    pub fn krb5_free_addresses(context: krb5_context,
                               val: *mut *mut krb5_address);
    // TODO: Doc
    pub fn krb5_free_authdata(context: krb5_context,
                              val: *mut *mut krb5_authdata);
    // TODO: Doc
    pub fn krb5_free_ticket(context: krb5_context,
                            val: *mut krb5_ticket);
    // TODO: Doc
    pub fn krb5_free_error(context: krb5_context,
                           val: *mut krb5_error);
    // TODO: Doc
    pub fn krb5_free_creds(context: krb5_context,
                           val: *mut krb5_creds);
    // TODO: Doc
    pub fn krb5_free_cred_contents(context: krb5_context,
                                   val: *mut krb5_creds);
    // TODO: Doc
    pub fn krb5_free_checksum(context: krb5_context,
                              val: *mut krb5_checksum);
    // TODO: Doc
    pub fn krb5_free_checksum_contents(context: krb5_context,
                                       val: *mut krb5_checksum);
    // TODO: Doc
    pub fn krb5_free_keyblock(context: krb5_context,
                              val: *mut krb5_keyblock);
    // TODO: Doc
    pub fn krb5_free_keyblock_contents(context: krb5_context,
                                       val: *mut krb5_keyblock);
    // TODO: Doc
    pub fn krb5_free_ap_rep_enc_part(context: krb5_context,
                                     val: *mut krb5_ap_rep_enc_part);
    // TODO: Doc
    pub fn krb5_free_data(context: krb5_context,
                          val: *mut krb5_data);
    // TODO: Doc
    pub fn krb5_free_octet_data(context: krb5_context,
                                val: *mut krb5_octet_data);
    // TODO: Doc
    pub fn krb5_free_data_contents(context: krb5_context,
                                   val: *mut krb5_data);
    // TODO: Doc
    pub fn krb5_free_unparsed_name(context: krb5_context,
                                   val: *mut c_char);
    // TODO: Doc
    pub fn krb5_free_string(context: krb5_context,
                            val: *mut c_char);
    // TODO: Doc
    pub fn krb5_free_enctypes(context: krb5_context,
                              val: *mut krb5_enctype);
    // TODO: Doc
    pub fn krb5_free_cksumtypes(context: krb5_context,
                                val: *mut krb5_cksumtype);
    // TODO: Doc
    pub fn krb5_us_timeofday(context: krb5_context,
                             seconds: *mut krb5_timestamp,
                             microseconds: *mut krb5_int32) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_timeofday(context: krb5_context,
                          timeret: *mut krb5_timestamp) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_check_clockskew(context: krb5_context,
                                date: krb5_timestamp) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_os_localaddr(context: krb5_context,
                             addr: *mut *mut *mut krb5_address) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_default_realm(context: krb5_context,
                                  lrealm: *mut *mut c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_set_default_realm(context: krb5_context,
                                  lrealm: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_free_default_realm(context: krb5_context,
                                   lrealm: *mut c_char);
    // TODO: Doc
    pub fn krb5_sname_to_principal(context: krb5_context,
                                   hostname: *const c_char,
                                   sname: *const c_char,
                                   type_: krb5_int32,
                                   ret_princ: *mut krb5_principal) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_sname_match(context: krb5_context,
                            matching: krb5_const_principal,
                            princ: krb5_const_principal) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_change_password(context: krb5_context,
                                creds: *mut krb5_creds,
                                newpw: *mut c_char,
                                result_code: *mut c_int,
                                result_code_string: *mut krb5_data,
                                result_string: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_set_password(context: krb5_context,
                             creds: *mut krb5_creds,
                             newpw: *mut c_char,
                             change_password_for: krb5_principal,
                             result_code: *mut c_int,
                             result_code_string: *mut krb5_data,
                             result_string: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_set_password_useing_ccache(context: krb5_context,
                                           ccache: krb5_ccache,
                                           newpw: *mut c_char,
                                           change_password_for: krb5_principal,
                                           result_code: *mut c_int,
                                           result_code_string: *mut krb5_data,
                                           result_string: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_chpw_message(context: krb5_context,
                             server_string: *const krb5_data,
                             message_out: *mut *mut c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_profile(context: krb5_context,
                            profile: *mut *mut _profile_t) -> krb5_error_code;

    // TODO: Doc
    #[cfg(feature = "krb5_deprecated")]
    #[deprectated]
    pub fn krb5_get_in_tkt_with_password(context: krb5_context,
                                         options: krb5_flags,
                                         addrs: *mut *const krb5_address,
                                         ktypes: *mut krb5_enctype,
                                         pre_auth_types: *mut krb5_preauthtype,
                                         password: *const c_char,
                                         ccache: krb5_ccache,
                                         creds: *mut krb5_creds,
                                         ret_as_reply: *mut *mut krb5_kdc_rep) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_deprecated")]
    #[deprectated]
    pub fn krb5_get_in_tkt_with_skey(context: krb5_context,
                                     options: krb5_flags,
                                     addrs: *mut *const krb5_address,
                                     ktypes: *mut krb5_enctype,
                                     pre_auth_types: *mut krb5_preauthtype,
                                     password: *const c_char,
                                     ccache: krb5_ccache,
                                     creds: *mut krb5_creds,
                                     ret_as_reply: *mut *mut krb5_kdc_rep) -> krb5_error_code;
    // krb5/krb5.h:5133
    // TODO: Doc
    #[cfg(feature = "krb5_deprecated")]
    #[deprectated]
    pub fn krb5_get_in_tkt_with_keytab(context: krb5_context,
                                       options: krb5_flags,
                                       addrs: *mut *const krb5_address,
                                       ktypes: *mut krb5_enctype,
                                       pre_auth_types: *mut krb5_preauthtype,
                                       arg_keytab: krb5_keytab,
                                       ccache: krb5_ccache,
                                       creds: *mut krb5_creds,
                                       ret_as_reply: *mut *mut krb5_kdc_rep) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_rd_req(context: krb5_context,
                       auht_context: *mut krb5_auth_context,
                       inbuf: *const krb5_data,
                       server: krb5_const_principal,
                       keytab: krb5_keytab,
                       ap_req_options: *mut krb5_flags,
                       ticket: *mut *mut krb5_ticket) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kt_read_service_key(context: krb5_context,
                                    keyprocarg: krb5_pointer,
                                    principal: krb5_principal,
                                    vno: krb5_kvno,
                                    enctype: krb5_enctype,
                                    key: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_safe(context: krb5_context,
                        auth_context: krb5_auth_context,
                        userdata: *mut krb5_data,
                        outbuf: *mut krb5_data,
                        outdat: krb5_replay_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_priv(context: krb5_context,
                        auth_context: krb5_auth_context,
                        userdata: *const krb5_data,
                        outbuf: *mut krb5_data,
                        outdata: *mut krb5_replay_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_sendauth(context: krb5_context,
                         auth_context: *mut krb5_auth_context,
                         fd: krb5_pointer,
                         aapl_version: *mut c_char,
                         client: krb5_principal,
                         server: krb5_principal,
                         ap_req_options: krb5_flags,
                         in_data: *mut krb5_data,
                         in_creds: *mut krb5_creds,
                         ccache: krb5_ccache,
                         error: *mut *mut krb5_error,
                         rep_result: *mut *mut krb5_ap_rep_enc_part,
                         out_creds: *mut *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_recvauth(context: krb5_context,
                         auth_context: krb5_auth_context,
                         fd: krb5_pointer,
                         appl_version: *mut c_char,
                         server: krb5_principal,
                         flags: krb5_int32,
                         keytab: krb5_keytab,
                         ticket: *mut *mut krb5_ticket) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_recvauth_version(context: krb5_context,
                                 auth_context: *mut krb5_auth_context,
                                 fd: krb5_pointer,
                                 server: krb5_principal,
                                 flags: krb5_int32,
                                 keytab: krb5_keytab,
                                 ticket: *mut *mut krb5_ticket,
                                 version: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_ncred(context: krb5_context,
                         auth_context: krb5_auth_context,
                         ppcreds: *mut *mut krb5_creds,
                         ppdata: *mut *mut krb5_data,
                         outdata: *mut krb5_replay_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_mk_1cred(context: krb5_context,
                         auth_context: krb5_auth_context,
                         pcreds: *mut krb5_creds,
                         ppdata: *mut *mut krb5_data,
                         outdata: *mut krb5_replay_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_rd_cred(context: krb5_context,
                        auth_context: krb5_auth_context,
                        pcreddata: *mut krb5_data,
                        pppcreds: *mut *mut *mut krb5_creds,
                        outdata: *mut krb5_replay_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_fwd_tgt_creds(context: krb5_context,
                              auth_context: krb5_auth_context,
                              rhost: *mut c_char,
                              client: krb5_principal,
                              server: krb5_principal,
                              cc: krb5_ccache,
                              forwardable: c_int,
                              outbuf: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_init(context: krb5_context,
                              auth_context: *mut krb5_auth_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_free(context: krb5_context,
                              auth_context: krb5_auth_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setflags(context: krb5_context,
                                  auth_context: krb5_auth_context,
                                  flags: krb5_int32) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getflags(context: krb5_context,
                                  auth_context: krb5_auth_context,
                                  flags: *mut krb5_int32) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_set_checksum_func(context: krb5_context,
                                           auth_context: krb5_auth_context,
                                           func: Option<krb5_mk_req_checksum_func>,
                                           data: *mut c_void) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_get_checksum_func(context: krb5_context,
                                           auth_context: krb5_auth_context,
                                           func: *mut Option<krb5_mk_req_checksum_func>,
                                           data: *mut *mut c_void) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setaddrs(context: krb5_context,
                                  auth_context: krb5_auth_context,
                                  local_addr: *mut krb5_address,
                                  remote_addr: *mut krb5_address) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getaddrs(context: krb5_context,
                                  auth_context: krb5_auth_context,
                                  local_addr: *mut *mut krb5_address,
                                  remote_addr: *mut *mut krb5_address) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setports(context: krb5_context,
                                  auth_context: krb5_auth_context,
                                  local_port: *mut krb5_address,
                                  remote_port: *mut krb5_address) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setuseruserkey(context: krb5_context,
                                        auth_context: krb5_auth_context,
                                        keyblock: *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getkey(context: krb5_context,
                                auth_context: krb5_auth_context,
                                keyblock: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getkey_k(context: krb5_context,
                                  auth_context: krb5_auth_context,
                                  key: *mut krb5_key) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getsendsubkey(ctx: krb5_context,
                                       ac: krb5_auth_context,
                                       keyblock: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getsendsubkey_k(ctx: krb5_context,
                                         ac: krb5_auth_context,
                                         key: *mut krb5_key) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getrecvsubkey(ctx: krb5_context,
                                       ac: krb5_auth_context,
                                       keyblock: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getrecvsubkey_k(ctx: krb5_context,
                                         ac: krb5_auth_context,
                                         key: *mut krb5_key) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setsendsubkey(ctx: krb5_context,
                                       ac: krb5_auth_context,
                                       keyblock: *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setsendsubkey_k(ctx: krb5_context,
                                         ac: krb5_auth_context,
                                         key: krb5_key) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setrecvsubkey(ctx: krb5_context,
                                       ac: krb5_auth_context,
                                       keyblock: *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setrecvsubkey_k(ctx: krb5_context,
                                         ac: krb5_auth_context,
                                         key: krb5_key) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_deprecated")]
    #[deprecated]
    pub fn krb5_auth_con_getlocalsubkey(context: krb5_context,
                                        auth_context: krb5_auth_context,
                                        keyblock: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_deprecated")]
    #[deprecated]
    pub fn krb5_auth_con_getremotesubkey(context: krb5_context,
                                         auth_context: krb5_auth_context,
                                         keyblock: *mut *mut krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getlocalseqnumber(context: krb5_context,
                                           auth_context: krb5_auth_context,
                                           seqnumber: *mut krb5_int32) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getremoteseqnumber(context: krb5_context,
                                            auth_context: krb5_auth_context,
                                            seqnumber: *mut krb5_int32) -> krb5_error_code;
    // TODO: Doc
    #[cfg(feature = "krb5_deprecated")]
    #[deprecated]
    pub fn krb5_auth_con_initivector(context: krb5_context,
                                     auth_context: krb5_auth_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_setrcache(context: krb5_context,
                                   auth_context: krb5_auth_context,
                                   rcache: krb5_rcache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getrcache(context: krb5_context,
                                   auth_context: krb5_auth_context,
                                   rcache: *mut krb5_rcache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_getauthenticator(context: krb5_context,
                                          auth_context: krb5_auth_context,
                                          authenticator: *mut *mut krb5_authenticator) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_auth_con_set_req_cksumtype(context: krb5_context,
                                           auth_context: krb5_auth_context,
                                           cksumtype: krb5_cksumtype) -> krb5_error_code;
}

pub const KRB5_REALM_BRANCH_CHAR: c_char = b'.' as c_char;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_read_password(context: krb5_context,
                              prompt: *const c_char,
                              prompt2: *const c_char,
                              return_pwd: *mut c_char,
                              size_return: *mut c_uint) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_aname_to_localname(context: krb5_context,
                                   aname: krb5_const_principal,
                                   lnsize_in: c_int,
                                   lname: *mut c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_host_realm(context: krb5_error_code,
                               host: *const c_char,
                               realmsp: *mut *mut *mut c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_fallback_host_realm(context: krb5_context,
                                        hdata: *mut krb5_data,
                                        realmsp: *mut *mut *mut c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_free_host_realm(context: krb5_context,
                                realmlist: *mut *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_kuserok(context: krb5_error_code,
                        principal: krb5_principal,
                        luser: *const c_char) -> krb5_boolean;
    // TODO: Doc
    pub fn krb5_auth_con_getnaddrs(context: krb5_context,
                                   auth_context: krb5_auth_context,
                                   infd: c_int,
                                   flags: c_int) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_set_real_time(context: krb5_context,
                              seconds: krb5_timestamp,
                              microseconds: krb5_int32) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_time_offsets(context: krb5_context,
                                 seconds: *mut krb5_timestamp,
                                 microseconds: *mut krb5_int32) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_string_to_enctype(string: *mut c_char,
                                  enctypep: *mut krb5_enctype) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_string_to_salttype(string: *mut c_char,
                                   salttypep: *mut krb5_int32) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_string_to_cksumtypep(string: *mut c_char,
                                     cksumtypep: *mut krb5_cksumtype) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_string_to_timestamp(string: *mut c_char,
                                    timestamp: *mut krb5_timestamp) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_string_to_deltat(string: *mut c_char,
                                 deltatp: *mut krb5_deltat) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_enctype_to_string(enctype: krb5_enctype,
                                  buffer: *mut c_char,
                                  buflen: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_enctype_to_name(enctype: krb5_enctype,
                                shortest: krb5_boolean,
                                buffer: *mut c_char,
                                buflen: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_salttype_to_string(salttype: krb5_int32,
                                   buffer: *mut c_char,
                                   buflen: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_cksumtype_to_string(cksumtype: krb5_cksumtype,
                                    buffer: *mut c_char,
                                    buflen: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_timestamp_to_string(timestamp: krb5_timestamp,
                                    buffer: *mut c_char,
                                    buflen: usize) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_timestamp_to_sfstring(timestamp: krb5_timestamp,
                                      buffer: *mut c_char,
                                      buflen: usize,
                                      pad: *mut c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_deltat_to_string(deltat: krb5_deltat,
                                 buffer: *mut c_char,
                                 buflen: usize) -> krb5_error_code;
}

// TODO: `KRB5_TGS_NAME` constant

pub const KRB5_TGS_NAME_SIZE: usize = 6;

pub const KRB5_RECVAUTH_SKIP_VERSION: krb5_flags = 0x0001;
pub const KRB5_RECVAUTH_BADAUTHVERS: krb5_flags = 0x0002;
// TODO: Doc
#[repr(C)]
pub struct krb5_prompt {
    pub prompt: *mut c_char,
    pub hidden: c_int,
    pub reply: *mut krb5_data,
}

// NOTE: last argument is actually `krb5_prompt prompts[]` in the orignal source,
//       But this should be equivalent.
pub type krb5_prompter_fct = extern "C" fn(context: krb5_context,
                                           data: *mut c_void,
                                           name: *const c_char,
                                           banner: *const c_char,
                                           num_prompts: c_int,
                                           prompts: *mut krb5_prompt) -> krb5_error_code;
#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    // NOTE: last argument is actually `krb5_prompt prompts[]` in the orignal source,
    //       But this should be equivalent.
    pub fn krb5_prompter_posix(context: krb5_context,
                               data: *mut c_void,
                               name: *const c_char,
                               banner: *const c_char,
                               num_prompts: c_int,
                               prompts: *mut krb5_prompt) -> krb5_error_code;
}

// TODO: `KRB5_RESPONDER_QUESTION_PASSWRD` constant
// TODO: `KRB5_RESPONDER_QUESTION_OTP` constant

// TODO: Doc
pub const KRB5_RESPONDER_OTP_FORMAT_DECIMAL: krb5_flags = 0;
// TODO: Doc
pub const KRB5_RESPONDER_OTP_FORMAT_HEXADECIMAL: krb5_flags = 1;
// TODO: Doc
pub const KRB5_RESPONDER_OTP_FORMAT_ALPHANUMERIC: krb5_flags = 2;

// TODO: Doc
pub const KRB5_RESPONDER_OTP_FLAGS_COLLECT_TOKEN: krb5_flags = 0x0001;
// TODO: Doc
pub const KRB5_RESPONDER_OTP_FLAGS_COLLECT_PIN: krb5_flags = 0x0002;
// TODO: Doc
pub const KRB5_RESPONDER_OTP_FLAGS_NEXTOTP: krb5_flags = 0x0004;
// TODO: Doc
pub const KRB5_RESPONDER_OTP_FLAGS_SEPERATE_PIN: krb5_flags = 0x0008;

// TODO: `KRB5_RESPONDER_QUESTION_PKINIT` cosntant

// TODO: Doc
pub const KRB5_RESPONDER_PKINIT_FLAGS_TOKEN_USER_PIN_COUNT_LOW: krb5_flags = (1 << 0);
// TODO: Doc
pub const KRB5_RESPONDER_PKINIT_FLAGS_TOKEN_USER_PIN_FINAL_TRY: krb5_flags = (1 << 1);
// TODO: Doc
pub const KRB5_RESPONDER_PKINIT_FLAGS_TOKEN_USER_PIN_LOCKED: krb5_flags = (1 << 2);

// TODO: Doc
// NOTE: where is `krb5_respoinder_context_st` really defined?
//       I cannot find it in the orignal source file.
//       Opaque struct for now
pub enum krb5_responder_context_st {}
pub type krb5_responder_context = *mut krb5_responder_context_st;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_responder_list_questions(ctx: krb5_context,
                                         rctx: krb5_responder_context) -> *const *const c_char;
    // TODO: Doc
    pub fn krb5_responder_get_challenge(ctx: krb5_context,
                                        rctx: krb5_responder_context,
                                        question: *const c_char) -> *const c_char;
    // TODO: Doc
    pub fn krb5_responder_set_answer(ctx: krb5_context,
                                     rctx: krb5_responder_context,
                                     question: *const c_char,
                                     answer: *const c_char) -> krb5_error_code;
}

// TODO: Doc
pub type krb5_responder_fn = extern "C" fn(ctx: krb5_context,
                                           data: *mut c_void,
                                           rctx: krb5_responder_context) -> krb5_error_code;

// TODO: Doc
#[repr(C)]
pub struct krb5_responder_otp_tokeninfo {
    pub flags: krb5_flags,
    pub format: krb5_int32,
    pub length: krb5_int32,
    pub vendor: *mut c_char,
    pub challenge: *mut c_char,
    pub token_id: *mut c_char,
    pub alg_id: *mut c_char,
}

// TODO: Doc
#[repr(C)]
pub struct krb5_responder_otp_challenge {
    pub service: *mut c_char,
    pub tokeninfo: *mut *mut krb5_responder_otp_challenge,
}

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_responder_otp_get_challenge(ctx: krb5_context,
                                            rctx: krb5_responder_context,
                                            chl: *mut *mut krb5_responder_otp_challenge) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_responder_otp_set_answer(ctx: krb5_context,
                                         rctx: krb5_responder_context,
                                         ti: usize,
                                         value: *const c_char,
                                         pin: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_responder_otp_challenge_free(ctx: krb5_context,
                                             rctx: krb5_responder_context,
                                             chl: *mut krb5_responder_otp_challenge);

}

// TODO: Doc
#[repr(C)]
pub struct krb5_responder_pkinit_identity {
    pub identity: *mut c_char,
    pub token_flags: krb5_int32,
}

// TODO: Doc
#[repr(C)]
pub struct krb5_responder_pkinit_challenge {
    pub identities: *mut *mut krb5_responder_pkinit_identity,
}

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_responder_pkinit_get_challenge(ctx: krb5_context,
                                               rctx: krb5_responder_context,
                                               chl_out: *mut *mut krb5_responder_pkinit_challenge) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_responder_pkinit_set_answer(ctx: krb5_context,
                                            rctx: krb5_responder_context,
                                            identity: *const c_char,
                                            pin: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_responder_pkinit_challenge_free(ctx: krb5_context,
                                                rctx: krb5_responder_context,
                                                chl: *mut krb5_responder_pkinit_identity);
}

// TODO: Doc
#[repr(C)]
pub struct krb5_get_init_creds_opt {
    pub flags: krb5_flags,
    pub tkt_life: krb5_deltat,
    pub renew_life: krb5_deltat,
    pub forwardable: c_int,
    pub proxiable: c_int,
    pub etype_list: *mut krb5_enctype,
    pub etype_list_length: c_int,
    pub address_list: *mut *mut krb5_address,
    pub preauth_list: *mut krb5_preauthtype,
    pub preauth_list_length: c_int,
    pub salt: *mut krb5_data,
}

pub const KRB5_GET_INIT_CREDS_OPT_TKT_LIFE: krb5_flags      = 0x0001;
pub const KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE: krb5_flags    = 0x0002;
pub const KRB5_GET_INIT_CREDS_OPT_FORWARDABLE: krb5_flags   = 0x0004;
pub const KRB5_GET_INIT_CREDS_OPT_PROXIABLE: krb5_flags     = 0x0008;
pub const KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST: krb5_flags    = 0x0010;
pub const KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST: krb5_flags  = 0x0020;
pub const KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST: krb5_flags  = 0x0040;
pub const KRB5_GET_INIT_CREDS_OPT_SALT: krb5_flags          = 0x0080;
pub const KRB5_GET_INIT_CREDS_OPT_CHG_PWD_PRMPT: krb5_flags = 0x0100;
pub const KRB5_GET_INIT_CREDS_OPT_CANONICALIZE: krb5_flags  = 0x0200;
pub const KRB5_GET_INIT_CREDS_OPT_ANONYMOUS: krb5_flags     = 0x0400;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_alloc(context: krb5_context,
                                         opt: *mut *mut krb5_get_init_creds_opt) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_free(context: krb5_context,
                                        opt: *mut krb5_get_init_creds_opt);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_tkt_life(opt: *mut krb5_get_init_creds_opt,
                                                tkt_life: krb5_deltat);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_renew_life(opt: *mut krb5_get_init_creds_opt,
                                                  renew_life: krb5_deltat);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_forwardable(opt: *mut krb5_get_init_creds_opt,
                                                   forwardable: c_int);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_proxiable(opt: *mut krb5_get_init_creds_opt,
                                                 proxiable: c_int);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_canonicalize(opt: *mut krb5_get_init_creds_opt,
                                                    canonicalize: c_int);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_anonymous(opt: *mut krb5_get_init_creds_opt,
                                                 anonymous: c_int);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_etype_list(opt: *mut krb5_get_init_creds_opt,
                                                  etype_list: *mut krb5_enctype,
                                                  etype_list_length: c_int);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_address_list(opt: *mut krb5_get_init_creds_opt,
                                                    addresses: *mut *mut krb5_address);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_preauth_list(opt: *mut krb5_get_init_creds_opt,
                                                    preauth_list: *mut krb5_preauthtype,
                                                    preauth_list_length: c_int);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_salt(opt: *mut krb5_get_init_creds_opt,
                                            salt: *mut krb5_data);
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_change_password_prompt(opt: *mut krb5_get_init_creds_opt,
                                                              prompt: c_int);
}

// TODO: Doc
#[repr(C)]
pub struct krb5_gic_opt_pa_data {
    pub attr: *mut c_char,
    pub value: *mut c_char,
}

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_pa(context: krb5_context,
                                          opt: *mut krb5_get_init_creds_opt,
                                          attr: *const c_char,
                                          value: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_fast_ccache_name(context: krb5_context,
                                                        opt: *mut krb5_get_init_creds_opt,
                                                        fast_ccache_name: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_fast_ccache(context: krb5_context,
                                                   opt: *mut krb5_get_init_creds_opt,
                                                   ccache: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_in_ccache(context: krb5_context,
                                                 opt: *mut krb5_get_init_creds_opt,
                                                 ccache: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_out_ccache(context: krb5_context,
                                                  opt: *mut krb5_get_init_creds_opt,
                                                  ccache: krb5_ccache) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_fast_flags(context: krb5_context,
                                                  opt: *mut krb5_get_init_creds_opt,
                                                  flags: krb5_flags) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_get_fast_flags(context: krb5_context,
                                                  opt: *mut krb5_get_init_creds_opt,
                                                  out_flags: *mut krb5_flags) -> krb5_error_code;
}

// TODO: Doc
pub const KRB5_FAST_REQUIRED: krb5_flags = 0x0001;

type krb5_expire_callback_func = extern "C" fn(context: krb5_context,
                                               data: *mut c_void,
                                               password_expiration: krb5_timestamp,
                                               account_expiration: krb5_timestamp,
                                               is_last_req: krb5_boolean);
#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_expire_callback(context: krb5_context,
                                                       opt: *mut krb5_get_init_creds_opt,
                                                       cb: krb5_expire_callback_func,
                                                       data: *mut c_void) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_opt_set_responder(context: krb5_context,
                                                 opt: *mut krb5_get_init_creds_opt,
                                                 responder: Option<krb5_responder_fn>,
                                                 data: *mut c_void) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_password(context: krb5_context,
                                        creds: *mut krb5_creds,
                                        client: krb5_principal,
                                        password: *const c_char,
                                        prompter: Option<krb5_prompter_fct>,
                                        data: *mut c_void,
                                        start_time: krb5_deltat,
                                        in_tkt_service: *const c_char,
                                        k5_gic_options: *const krb5_get_init_creds_opt) -> krb5_error_code;
}

pub enum _krb5_init_creds_context {}
pub type krb5_init_creds_context = *mut _krb5_init_creds_context;

// TODO: Doc
pub const KRB5_INIT_CREDS_STEP_FLAG_CONTINUE: krb5_flags = 0x1;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_init_creds_free(context: krb5_context,
                                ctx: krb5_init_creds_context);
    // TODO: Doc
    pub fn krb5_init_creds_get(context: krb5_context,
                               ctx: krb5_init_creds_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_creds_get_creds(context: krb5_context,
                                     ctx: krb5_init_creds_context,
                                     creds: *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_creds_get_error(context: krb5_context,
                                     ctx: krb5_init_creds_context,
                                     error: *mut *mut krb5_error) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_creds_init(context: krb5_context,
                                client: krb5_principal,
                                prompter: Option<krb5_prompter_fct>,
                                data: *mut c_void,
                                start_time: krb5_deltat,
                                options: *mut krb5_get_init_creds_opt,
                                ctx: *mut krb5_init_creds_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_creds_set_keytab(context: krb5_context,
                                      ctx: krb5_init_creds_context,
                                      keytab: krb5_keytab) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_creds_step(context: krb5_context,
                                ctx: krb5_init_creds_context,
                                in_: *mut krb5_data,
                                out: *mut krb5_data,
                                realm: *mut krb5_data,
                                flags: *mut c_uint) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_creds_set_password(context: krb5_context,
                                        ctx: krb5_init_creds_context,
                                        password: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_creds_set_service(context: krb5_context,
                                       ctx: krb5_init_creds_context,
                                       service: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_init_creds_get_times(context: krb5_context,
                                     ctx: krb5_init_creds_context,
                                     times: *mut krb5_ticket_times) -> krb5_error_code;
}

pub enum _krb5_tkt_creds_context {}
pub type krb5_tkt_creds_context = *mut _krb5_tkt_creds_context;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_tkt_creds_init(context: krb5_context,
                               ccache: krb5_ccache,
                               creds: *mut krb5_creds,
                               options: krb5_flags,
                               ctx: krb5_tkt_creds_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_tkt_creds_get(context: krb5_context,
                              ctx: krb5_tkt_creds_context) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_tkt_creds_get_creds(context: krb5_context,
                                    ctx: krb5_tkt_creds_context,
                                    creds: *mut krb5_creds) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_tkt_creds_free(context: krb5_context,
                               ctx: krb5_tkt_creds_context);
}

// TODO: Doc
pub const KRB5_TKT_CREDS_STEP_FLAG_CONTINUE: krb5_flags = 0x1;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_tkt_creds_step(context: krb5_context,
                               ctx: krb5_tkt_creds_context,
                               in_: *mut krb5_data,
                               out: *mut krb5_data,
                               realm: *mut krb5_data,
                               flags: *mut c_uint) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_tkt_creds_get_times(context: krb5_context,
                                    ctx: krb5_tkt_creds_context,
                                    times: *mut krb5_ticket_times) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_init_creds_keytab(context: krb5_context,
                                      creds: *mut krb5_creds,
                                      client: krb5_principal,
                                      arg_keytab: krb5_keytab,
                                      start_time: krb5_deltat,
                                      in_tkt_service: *const c_char,
                                      k5_gic_options: *const krb5_get_init_creds_opt) -> krb5_error_code;
}

// TODO: Docs
#[repr(C)]
pub struct krb5_verify_init_creds_opt {
    pub flags: krb5_flags,
    pub ap_req_nofail: c_int,
}

// TODO: Doc
pub const KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL: krb5_flags = 0x0001;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_verify_init_creds_opt_init(k5_vic_options: *mut krb5_verify_init_creds_opt);
    // TODO: Doc
    pub fn krb5_verify_init_creds_opt_set_ap_req_nofail(k5_vic_options: *mut krb5_verify_init_creds_opt,
                                                        ap_req_nofail: c_int);
    // TODO: Doc
    pub fn krb5_verify_init_creds(context: krb5_context,
                                  creds: *mut krb5_creds,
                                  server: krb5_principal,
                                  keytab: krb5_keytab,
                                  ccache: *mut krb5_ccache,
                                  options: *mut krb5_verify_init_creds_opt) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_validated_creds(context: krb5_context,
                                    creds: *mut krb5_creds,
                                    client: krb5_principal,
                                    ccache: krb5_ccache,
                                    in_tkt_service: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_get_renewed_creds(context: krb5_context,
                                  creds: *mut krb5_creds,
                                  client: krb5_principal,
                                  ccache: krb5_ccache,
                                  in_tkt_service: *const c_char) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_decode_ticket(code: *const krb5_data,
                              rep: *mut *mut krb5_ticket) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_appdefault_string(context: krb5_context,
                                  appname: *const c_char,
                                  realm: *const krb5_data,
                                  option: *const c_char,
                                  default_value: *const c_char,
                                  ret_value: *mut *mut c_char);
    // TODO: Doc
    pub fn krb5_appdefault_boolean(context: krb5_context,
                                   appname: *const c_char,
                                   realm: *const krb5_data,
                                   option: *const c_char,
                                   default_value: c_int,
                                   ret_value: *mut c_int);
}

// TODO: Doc
pub const KRB5_PROMPT_TYPE_PASSWORD: krb5_prompt_type = 0x1;
// TODO: Doc
pub const KRB5_PROMPT_TYPE_NEW_PASSWORD: krb5_prompt_type = 0x2;
// TODO: Doc
pub const KRB5_PROMPT_TYPE_NEW_PASSWORD_AGAIN: krb5_prompt_type = 0x3;
// TODO: Doc
pub const KRB5_PROMPT_TYPE_PREAUTH: krb5_prompt_type = 0x4;

pub type krb5_prompt_type = krb5_int32;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_get_prompt_types(context: krb5_context) -> *mut krb5_prompt_type;
    // TODO: Doc
    pub fn krb5_set_error_message(ctx: krb5_context,
                                  code: krb5_error_code,
                                  fmt: *const c_char, ...);
    // TODO: Doc
    // TODO: `krb5_vset_error_message` function (va_list)!

    // TODO: Doc
    pub fn krb5_copy_error_message(dest_ctx: krb5_context,
                                   src_ctx: krb5_context);
    // TODO: Doc
    pub fn krb5_get_error_message(ctx: krb5_context,
                                  code: krb5_error_code) -> *const c_char;
    // TODO: Doc
    pub fn krb5_free_error_message(ctx: krb5_context,
                                   msg: *const c_char);
    // TODO: Doc
    pub fn krb5_clear_error_message(ctx: krb5_context);
    // TODO: Doc
    pub fn krb5_decode_authdata_container(context: krb5_context,
                                          type_: krb5_authdatatype,
                                          container: *const krb5_authdata,
                                          authdata: *mut *mut *mut krb5_authdata) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_make_authdata_kdc_issued(context: krb5_context,
                                         key: *const krb5_keyblock,
                                         issuer: krb5_const_principal,
                                         authdata: *mut *const krb5_authdata,
                                         ad_kdcissued: *mut *mut *mut krb5_authdata) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_verify_authdata_kdc_issued(context: krb5_context,
                                           key: *const krb5_keyblock,
                                           ad_kdcissued: *const krb5_authdata,
                                           issuer: *mut krb5_principal,
                                           authdata: *mut *mut *mut krb5_authdata) -> krb5_error_code;
}

// TODO: Doc
pub const KRB5_PAC_LOGON_INFO: krb5_ui_4 = 1;
// TODO: Doc
pub const KRB5_PAC_CREDENTIALS_INFO: krb5_ui_4 = 2;
// TODO: Doc
pub const KRB5_PAC_SERVER_CHECKSUM: krb5_ui_4 = 6;
// TODO: Doc
pub const KRB5_PRIVSVR_CHECKSUM: krb5_ui_4 = 7;
// TODO: Doc
pub const KRB5_PAC_CLIENT_INFO: krb5_ui_4 = 10;
// TODO: Doc
pub const KRB5_PAC_DELEGATION_INFO: krb5_ui_4 = 11;
// TODO: Doc
pub const KRB5_PAC_UPN_DNS_INFO: krb5_ui_4 = 12;

pub enum krb5_pac_data {}
pub type krb5_pac = *mut krb5_pac_data;

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_pac_add_buffer(context: krb5_context,
                               pac: krb5_pac,
                               type_: krb5_ui_4,
                               data: *const krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_pac_free(context: krb5_context,
                         pac: krb5_pac);
    // TODO: Doc
    pub fn krb5_pac_get_buffer(context: krb5_context,
                               pac: krb5_pac,
                               type_: krb5_ui_4,
                               data: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_pac_get_types(context: krb5_context,
                              pac: krb5_pac,
                              len: *mut usize,
                              types: *mut *mut krb5_ui_4) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_pac_init(context: krb5_context,
                         pac: *mut krb5_pac) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_pac_parse(context: krb5_context,
                          ptr: *const c_void,
                          len: usize,
                          pac: *mut krb5_pac) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_pac_verify(context: krb5_context,
                           pac: krb5_pac,
                           authtime: krb5_timestamp,
                           principal: krb5_const_principal,
                           server: *const krb5_keyblock,
                           privsvr: *const krb5_keyblock) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_pac_sign(context: krb5_context,
                         pac: krb5_pac,
                         authtime: krb5_timestamp,
                         principal: krb5_const_principal,
                         server_key: *const krb5_keyblock,
                         privsvr_key: *const krb5_keyblock,
                         data: *mut krb5_data) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_allow_weak_crypt(context: krb5_context,
                                 enable: krb5_boolean) -> krb5_error_code;
}

// TODO: Docs
#[repr(C)]
pub struct krb5_trace_info {
    pub message: *const c_char,
}

pub type krb5_trace_callback = extern "C" fn(context: krb5_context,
                                             info: *const krb5_trace_info,
                                             cb_data: *mut c_void);
#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    pub fn krb5_set_trace_callback(context: krb5_context,
                                   fn_: Option<krb5_trace_callback>,
                                   cb_data: *mut c_void) -> krb5_error_code;
    // TODO: Doc
    pub fn krb5_set_trace_filename(context: krb5_context,
                                   filename: *const c_char) -> krb5_error_code;
}

// include <et/com_err.h>

pub const KRB5KDC_ERR_NONE: krb5_error_code                                = (-1765328384);
pub const KRB5KDC_ERR_NAME_EXP: krb5_error_code                            = (-1765328383);
pub const KRB5KDC_ERR_SERVICE_EXP: krb5_error_code                         = (-1765328382);
pub const KRB5KDC_ERR_BAD_PVNO: krb5_error_code                            = (-1765328381);
pub const KRB5KDC_ERR_C_OLD_MAST_KVNO: krb5_error_code                     = (-1765328380);
pub const KRB5KDC_ERR_S_OLD_MAST_KVNO: krb5_error_code                     = (-1765327379);
pub const KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN: krb5_error_code                 = (-1765328378);
pub const KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN: krb5_error_code                 = (-1765328377);
pub const KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE: krb5_error_code                = (-1765328376);
pub const KRB5KDC_ERR_NULL_KEY: krb5_error_code                            = (-1765328375);
pub const KRB5KDC_ERR_CANNOT_POSTDATE: krb5_error_code                     = (-1765328374);
pub const KRB5KDC_ERR_NEVER_VALID: krb5_error_code                         = (-1765328373);
pub const KRB5KDC_ERR_POLICY: krb5_error_code                              = (-1765328372);
pub const KRB5KDC_ERR_BADOPTION: krb5_error_code                           = (-1765328371);
pub const KRB5KDC_ERR_ETYPE_NOSUPP: krb5_error_code                        = (-1765328370);
pub const KRB5KDC_ERR_SUMTYPE_NOSUPP: krb5_error_code                      = (-1765328369);
pub const KRB5KDC_ERR_PADATA_TYPE_NOSUPP: krb5_error_code                  = (-1765328368);
pub const KRB5KDC_ERR_TRTYPE_NOSUPPP: krb5_error_code                      = (-1765328367);
pub const KRB5KDC_ERR_CLIENT_REVOKED: krb5_error_code                      = (-1765328366);
pub const KRB5KDC_ERR_SERVICE_REVOKED: krb5_error_code                     = (-1765328365);
pub const KRB5KDC_ERR_TGT_REVOKED: krb5_error_code                         = (-1765328364);
pub const KRB5KDC_ERR_CLIENT_NOTYET: krb5_error_code                       = (-1765328363);
pub const KRB5KDC_ERR_SERVICE_NOTYET: krb5_error_code                      = (-1765328362);
pub const KRB5KDC_ERR_KEY_EXP: krb5_error_code                             = (-1765328361);
pub const KRB5KDC_ERR_PREAUTH_FAILED: krb5_error_code                      = (-1765328360);
pub const KRB5KDC_ERR_PREAUTH_REQUIRED: krb5_error_code                    = (-1765328359);
pub const KRB5KDC_ERR_SERVER_NOMATCH: krb5_error_code                      = (-1765328358);
pub const KRB5KDC_ERR_MUST_USE_USER2USER: krb5_error_code                  = (-1765328357);
pub const KRB5KDC_ERR_PATH_NOT_ACCEPTED: krb5_error_code                   = (-1765328356);
pub const KRB5KDC_ERR_SVC_UNAVAILABLE: krb5_error_code                     = (-1765328355);
pub const KRB5PLACEHOLD_30: krb5_error_code                                = (-1765328354);
pub const KRB5KRB_AP_ERR_BAD_INTEGRITY: krb5_error_code                    = (-1765328353);
pub const KRB5KRB_AP_ERR_TKT_EXPIRED: krb5_error_code                      = (-1765328352);
pub const KRB5KRB_AP_ERR_TKT_NYV: krb5_error_code                          = (-1765328351);
pub const KRB5KRB_AP_ERR_REPEAT: krb5_error_code                           = (-1765328350);
pub const KRB5KRB_AP_ERR_NOT_US: krb5_error_code                           = (-1765328349);
pub const KRB5KRB_AP_ERR_BADMATCH: krb5_error_code                         = (-1765328348);
pub const KRB5KRB_AP_ERR_SKES: krb5_error_code                             = (-1765328347);
pub const KRB5KRB_AP_ERR_BADADDR: krb5_error_code                          = (-1765328346);
pub const KRB5KRB_AP_ERR_BADVERSION: krb5_error_code                       = (-1765328345);
pub const KRB5KRB_AP_ERR_MSG_TYPE: krb5_error_code                         = (-1765328344);
pub const KRB5KRB_AP_ERR_MODIFIED: krb5_error_code                         = (-1765328343);
pub const KRB5KRB_AP_ERR_BADORDER: krb5_error_code                         = (-1765328342);
pub const KRB5KRB_AP_ERR_ILL_CR_TKT: krb5_error_code                       = (-1765328341);
pub const KRB5KRB_AP_ERR_BADKEYVER: krb5_error_code                        = (-1765328340);
pub const KRB5KRB_AP_ERR_NOKEY: krb5_error_code                            = (-1765328339);
pub const KRB5KRB_AP_ERR_MUT_FAIL: krb5_error_code                         = (-1765328338);
pub const KRB5KRB_AP_ERR_BADDIRECTION: krb5_error_code                     = (-1765328337);
pub const KRB5KRB_AP_ERR_METHOD: krb5_error_code                           = (-1765328336);
pub const KRB5KRB_AP_ERR_BADSEQ: krb5_error_code                           = (-1765328335);
pub const KRB5KRB_AP_ERR_INAPP_CKSUM: krb5_error_code                      = (-1765328334);
pub const KRB5KRB_AP_PATH_NOT_ACCEPTED: krb5_error_code                    = (-1765328333);
pub const KRB5KRB_ERR_RESPONSE_TOO_BIG: krb5_error_code                    = (-1765328332);
pub const KRB5PLACEHOLD_53: krb5_error_code                                = (-1765328331);
pub const KRB5PLACEHOLD_54: krb5_error_code                                = (-1765328330);
pub const KRB5PLACEHOLD_55: krb5_error_code                                = (-1765328329);
pub const KRB5PLACEHOLD_56: krb5_error_code                                = (-1765328328);
pub const KRB5PLACEHOLD_57: krb5_error_code                                = (-1765328327);
pub const KRB5PLACEHOLD_58: krb5_error_code                                = (-1765328326);
pub const KRB5PLACEHOLD_59: krb5_error_code                                = (-1765328325);
pub const KRB5KRB_ERR_GENERIC: krb5_error_code                             = (-1765328324);
pub const KRB5KRB_ERR_FIELD_TOOLONG: krb5_error_code                       = (-1765328323);
pub const KRB5KRB_ERR_CLIENT_NOT_TRUSTED: krb5_error_code                  = (-1765328322);
pub const KRB5KRB_ERR_KDC_NOT_TRUSTED: krb5_error_code                     = (-1765328321);
pub const KRB5KRB_ERR_INVALID_SIG: krb5_error_code                         = (-1765328320);
pub const KRB5KRB_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED: krb5_error_code      = (-1765328319);
pub const KRB5KRB_ERR_CERTIFICATE_MISMATCH: krb5_error_code                = (-1765328318);
pub const KRB5KRB_AP_ERR_NO_TGT: krb5_error_code                           = (-1765328317);
pub const KRB5KDC_ERR_WRONG_REALM: krb5_error_code                         = (-1765328316);
pub const KRB5KRB_APP_ERR_USER_TO_USER_REQUIRED: krb5_error_code           = (-1765328315);
pub const KRB5KDC_ERR_CANT_VERIFY_CERTIFICATE: krb5_error_code             = (-1765328314);
pub const KRB5KDC_ERR_INVALID_CERTIFICATE: krb5_error_code                 = (-1765328313);
pub const KRB5KDC_ERR_REVOKED_CERTIFICATE: krb5_error_code                 = (-1765328312);
pub const KRB5KDC_ERR_REVOCATION_STATUS_UNKNOWN: krb5_error_code           = (-1765328311);
pub const KRB5KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: krb5_error_code       = (-1765328310);
pub const KRB5KDC_ERR_CLIENT_NAME_MISMATCH: krb5_error_code                = (-1765328309);
pub const KRB5KDC_ERR_KDC_NAME_MISMATCH: krb5_error_code                   = (-1765328308);
pub const KRB5KDC_ERR_INCONSISTENT_KEY_PURPOSE: krb5_error_code            = (-1765328307);
pub const KRB5KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED: krb5_error_code         = (-1765328306);
pub const KRB5KDC_ERR_PA_CHECKSUM_IN_CERT_NOT_ACCEPTED: krb5_error_code    = (-1765328305);
pub const KRB5KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED: krb5_error_code  = (-1765328304);
pub const KRB5KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED: krb5_error_code = (-1765328303);
pub const KRB5PLACEHOLD_82: krb5_error_code                                = (-1765328302);
pub const KRB5PLACEHOLD_83: krb5_error_code                                = (-1765328301);
pub const KRB5PLACEHOLD_84: krb5_error_code                                = (-1765328300);
pub const KRB5KRB_AP_ERR_IAKERB_KDC_NOT_FOUND: krb5_error_code             = (-1765328299);
pub const KRB5KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE: krb5_error_code           = (-1765328298);
pub const KRB5PLACEHOLD_87: krb5_error_code                                = (-1765328297);
pub const KRB5PLACEHOLD_88: krb5_error_code                                = (-1765328296);
pub const KRB5PLACEHOLD_89: krb5_error_code                                = (-1765328295);
pub const KRB5PLACEHOLD_90: krb5_error_code                                = (-1765328294);
pub const KRB5PLACEHOLD_91: krb5_error_code                                = (-1765328293);
pub const KRB5PLACEHOLD_92: krb5_error_code                                = (-1765328292);
pub const KRB5KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION: krb5_error_code        = (-1765328291);
pub const KRB5PLACEHOLD_94: krb5_error_code                                = (-1765328290);
pub const KRB5PLACEHOLD_95: krb5_error_code                                = (-1765328289);
pub const KRB5PLACEHOLD_96: krb5_error_code                                = (-1765328288);
pub const KRB5PLACEHOLD_97: krb5_error_code                                = (-1765328287);
pub const KRB5PLACEHOLD_98: krb5_error_code                                = (-1765328286);
pub const KRB5PLACEHOLD_99: krb5_error_code                                = (-1765328285);
pub const KRB5KDC_ERR_NO_ACCEPTABLE_KDF: krb5_error_code                   = (-1765328284);
pub const KRB5PLACEHOLD_101: krb5_error_code                               = (-1765328283);
pub const KRB5PLACEHOLD_102: krb5_error_code                               = (-1765328282);
pub const KRB5PLACEHOLD_103: krb5_error_code                               = (-1765328281);
pub const KRB5PLACEHOLD_104: krb5_error_code                               = (-1765328280);
pub const KRB5PLACEHOLD_105: krb5_error_code                               = (-1765328279);
pub const KRB5PLACEHOLD_106: krb5_error_code                               = (-1765328278);
pub const KRB5PLACEHOLD_107: krb5_error_code                               = (-1765328277);
pub const KRB5PLACEHOLD_108: krb5_error_code                               = (-1765328276);
pub const KRB5PLACEHOLD_109: krb5_error_code                               = (-1765328275);
pub const KRB5PLACEHOLD_110: krb5_error_code                               = (-1765328274);
pub const KRB5PLACEHOLD_111: krb5_error_code                               = (-1765328273);
pub const KRB5PLACEHOLD_112: krb5_error_code                               = (-1765328272);
pub const KRB5PLACEHOLD_113: krb5_error_code                               = (-1765328271);
pub const KRB5PLACEHOLD_114: krb5_error_code                               = (-1765328270);
pub const KRB5PLACEHOLD_115: krb5_error_code                               = (-1765328269);
pub const KRB5PLACEHOLD_116: krb5_error_code                               = (-1765328268);
pub const KRB5PLACEHOLD_117: krb5_error_code                               = (-1765328267);
pub const KRB5PLACEHOLD_118: krb5_error_code                               = (-1765328266);
pub const KRB5PLACEHOLD_119: krb5_error_code                               = (-1765328265);
pub const KRB5PLACEHOLD_120: krb5_error_code                               = (-1765328264);
pub const KRB5PLACEHOLD_121: krb5_error_code                               = (-1765328263);
pub const KRB5PLACEHOLD_122: krb5_error_code                               = (-1765328262);
pub const KRB5PLACEHOLD_123: krb5_error_code                               = (-1765328261);
pub const KRB5PLACEHOLD_124: krb5_error_code                               = (-1765328260);
pub const KRB5PLACEHOLD_125: krb5_error_code                               = (-1765328259);
pub const KRB5PLACEHOLD_126: krb5_error_code                               = (-1765328258);
pub const KRB5PLACEHOLD_127: krb5_error_code                               = (-1765328257);
pub const KRB5_ERR_RCSID: krb5_error_code                                  = (-1765328256);
pub const KRB5_LIBOS_BADLOCKFLAG: krb5_error_code                          = (-1765328255);
pub const KRB5_LIBOS_CANTREADPWD: krb5_error_code                          = (-1765328254);
pub const KRB5_LIBOS_BADPWDMATCH: krb5_error_code                          = (-1765328253);
pub const KRB5_LIBOS_PWDINTR: krb5_error_code                              = (-1765328252);
pub const KRB5_PARSE_ILLCHAR: krb5_error_code                              = (-1765328251);
pub const KRB5_PARSE_MALFORMED: krb5_error_code                            = (-1765328250);
pub const KRB5_CONFIG_CANTOPEN: krb5_error_code                            = (-1765328249);
pub const KRB5_CONFIG_BADFORMAT: krb5_error_code                           = (-1765328248);
pub const KRB5_CONFIG_NOTENUFSPACE: krb5_error_code                        = (-1765328247);
pub const KRB5_BADMSGTYPE: krb5_error_code                                 = (-1765328246);
pub const KRB5_CC_BADNAME: krb5_error_code                                 = (-1765328245);
pub const KRB5_CC_UNKNOWN_TYPE: krb5_error_code                            = (-1765328244);
pub const KRB5_CC_NOTFOUND: krb5_error_code                                = (-1765328243);
pub const KRB5_CC_END: krb5_error_code                                     = (-1765328242);
pub const KRB5_NO_TKT_SUPPLIED: krb5_error_code                            = (-1765328241);
pub const KRB5KRB_AP_WRONG_PRINC: krb5_error_code                          = (-1765328240);
pub const KRB5KRB_AP_ERR_TKT_INVALID: krb5_error_code                      = (-1765328239);
pub const KRB5_PRINC_NOMATCH: krb5_error_code                              = (-1765328238);
pub const KRB5_KDCREP_MODIFIED: krb5_error_code                            = (-1765328237);
pub const KRB5_KDCREP_SKEW: krb5_error_code                                = (-1765328236);
pub const KRB5_IN_TKT_REALM_MISMATCH: krb5_error_code                      = (-1765328235);
pub const KRB5_PROG_ETYPE_NOSUPP: krb5_error_code                          = (-1765328234);
pub const KRB5_PROG_KEYTYPE_NOSUPP: krb5_error_code                        = (-1765328233);
pub const KRB5_WRONG_ETYPE: krb5_error_code                                = (-1765328232);
pub const KRB5_PROG_SUMTYPE_NOSUPP: krb5_error_code                        = (-1765328231);
pub const KRB5_REALM_UNKNOWN: krb5_error_code                              = (-1765328230);
pub const KRB5_SERVICE_UNKNOWN: krb5_error_code                            = (-1765328229);
pub const KRB5_KDC_UNREACH: krb5_error_code                                = (-1765328228);
pub const KRB5_NO_LOCALNAME: krb5_error_code                               = (-1765328227);
pub const KRB5_MUTUAL_FAILED: krb5_error_code                              = (-1765328226);
pub const KRB5_RC_TYPE_EXISTS: krb5_error_code                             = (-1765328225);
pub const KRB5_RC_MALLOC: krb5_error_code                                  = (-1765328224);
pub const KRB5_RC_TYPE_NOTFOUND: krb5_error_code                           = (-1765328223);
pub const KRB5_RC_UNKNOWN: krb5_error_code                                 = (-1765328222);
pub const KRB5_RC_REPLAY: krb5_error_code                                  = (-1765328221);
pub const KRB5_RC_IO: krb5_error_code                                      = (-1765328220);
pub const KRB5_RC_NOIO: krb5_error_code                                    = (-1765328219);
pub const KRB5_RC_PARSE: krb5_error_code                                   = (-1765328218);
pub const KRB5_RC_IO_EOF: krb5_error_code                                  = (-1765328217);
pub const KRB5_RC_IO_MALLOC: krb5_error_code                               = (-1765328216);
pub const KRB5_RC_IO_PERM: krb5_error_code                                 = (-1765328215);
pub const KRB5_RC_IO_IO: krb5_error_code                                   = (-1765328214);
pub const KRB5_RC_IO_SPACE: krb5_error_code                                = (-1765328212);
pub const KRB5_TRANS_CANTOPEN: krb5_error_code                             = (-1765328211);
pub const KRB5_TRANS_BADFORMAT: krb5_error_code                            = (-1765328210);
pub const KRB5_LNAME_CANTOPEN: krb5_error_code                             = (-1765328209);
pub const KRB5_LNAME_NOTRANS: krb5_error_code                              = (-1765328208);
pub const KRB5_LNAME_BADFORMAT: krb5_error_code                            = (-1765328207);
pub const KRB5_CRYPTO_INTERNAL: krb5_error_code                            = (-1765328206);
pub const KRB5_KT_BADNAME: krb5_error_code                                 = (-1765328205);
pub const KRB5_KT_UNKNOWN_TYPE: krb5_error_code                            = (-1765328204);
pub const KRB5_KT_NOTFOUND: krb5_error_code                                = (-1765328203);
pub const KRB5_KT_END: krb5_error_code                                     = (-1765328202);
pub const KRB5_KT_NOWRITE: krb5_error_code                                 = (-1765328201);
pub const KRB5_KT_IOERR: krb5_error_code                                   = (-1765328200);
pub const KRB5_NO_TKT_IN_RLM: krb5_error_code                              = (-1765328199);
pub const KRB5DES_BAD_KEYPAR: krb5_error_code                              = (-1765328198);
pub const KRB5DES_WEAK_KEY: krb5_error_code                                = (-1765328197);
pub const KRB5_BAD_ENCTYPE: krb5_error_code                                = (-1765328196);
pub const KRB5_BAD_KEYSIZE: krb5_error_code                                = (-1765328195);
pub const KRB5_BAD_MSIZE: krb5_error_code                                  = (-1765328194);
pub const KRB5_CC_TYPE_EXISTS: krb5_error_code                             = (-1765328193);
pub const KRB5_KT_TYPE_EXISTS: krb5_error_code                             = (-1765328192);
pub const KRB5_CC_IO: krb5_error_code                                      = (-1765328191);
pub const KRB5_FCC_PERM: krb5_error_code                                   = (-1765328190);
pub const KRB5_FCC_NOFILE: krb5_error_code                                 = (-1765328189);
pub const KRB5_FCC_INTERNAL: krb5_error_code                               = (-1765328188);
pub const KRB5_CC_WRITE: krb5_error_code                                   = (-1765328187);
pub const KRB5_CC_NOMEM: krb5_error_code                                   = (-1765328186);
pub const KRB5_CC_FORMAT: krb5_error_code                                  = (-1765328185);
pub const KRB5_CC_NOT_KTYPE: krb5_error_code                               = (-1765328184);
pub const KRB5_INVALID_FLAGS: krb5_error_code                              = (-1765328183);
pub const KRB5_NO_2ND_TKT: krb5_error_code                                 = (-1765328182);
pub const KRB5_NOCREDS_SUPPLIED: krb5_error_code                           = (-1765328181);
pub const KRB5_SENDAUTH_BADAUTHVERS: krb5_error_code                       = (-1765328180);
pub const KRB5_SENDAUTH_BADAPPLVERS: krb5_error_code                       = (-1765328179);
pub const KRB5_SENDAUTH_BADRESPONSE: krb5_error_code                       = (-1765328178);
pub const KRB5_SENDAUTH_REJECTED: krb5_error_code                          = (-1765328177);
pub const KRB5_PREAUTH_BAD_TYPE: krb5_error_code                           = (-1765328176);
pub const KRB5_PREAUTH_NO_KEY: krb5_error_code                             = (-1765328175);
pub const KRB5_PREAUTH_FAILED: krb5_error_code                             = (-1765328174);
pub const KRB5_RCACHE_BADVNO: krb5_error_code                              = (-1765328173);
pub const KRB5_CCACHE_BADVNO: krb5_error_code                              = (-1765328172);
pub const KRB5_KEYTAB_BADVNO: krb5_error_code                              = (-1765328171);
pub const KRB5_PROG_ATYPE_NOSUPP: krb5_error_code                          = (-1765328170);
pub const KRB5_RC_REQUIRED: krb5_error_code                                = (-1765328169);
pub const KRB5_ERR_BAD_HOSTNAME: krb5_error_code                           = (-1765328168);
pub const KRB5_ERR_HOST_REALM_UNKNOWN: krb5_error_code                     = (-1765328167);
pub const KRB5_SNAME_UNSUPP_NAMETYPE: krb5_error_code                      = (-1765328166);
pub const KRB5KRB_AP_ERR_V4_REPLY: krb5_error_code                         = (-1765328165);
pub const KRB5_REALM_CANT_RESOLVE: krb5_error_code                         = (-1765328164);
pub const KRB5_TKT_NOT_FORWARDABLE: krb5_error_code                        = (-1765328163);
pub const KRB5_FWD_BAD_PRINCIPAL: krb5_error_code                          = (-1765328162);
pub const KRB5_GET_IN_TKT_LOOP: krb5_error_code                            = (-1765328161);
pub const KRB5_CONFIG_NODEFREALM: krb5_error_code                          = (-1765328160);
pub const KRB5_SAM_UNSUPPORTED: krb5_error_code                            = (-1765328159);
pub const KRB5_SAM_INVALID_ETYPE: krb5_error_code                          = (-1765328158);
pub const KRB5_SAM_NO_CHECKSUM: krb5_error_code                            = (-1765328157);
pub const KRB5_SAM_BAD_CHECKSUM: krb5_error_code                           = (-1765328156);
pub const KRB5_KT_NAME_TOOLONG: krb5_error_code                            = (-1765328155);
pub const KRB5_KT_KVNONOTFOUND: krb5_error_code                            = (-1765328154);
pub const KRB5_APPL_EXPIRED: krb5_error_code                               = (-1765328153);
pub const KRB5_LIB_EXPIRED: krb5_error_code                                = (-1765328152);
pub const KRB5_CHPW_PWDNULL: krb5_error_code                               = (-1765328151);
pub const KRB5_CHPW_FAIL: krb5_error_code                                  = (-1765328150);
pub const KRB5_KT_FORMAT: krb5_error_code                                  = (-1765328149);
pub const KRB5_NOPERM_ETYPE: krb5_error_code                               = (-1765328148);
pub const KRB5_CONFIG_ETYPE_NOSUPP: krb5_error_code                        = (-1765328147);
pub const KRB5_OBSOLETE_FN: krb5_error_code                                = (-1765328146);
pub const KRB5_EAI_FAIL: krb5_error_code                                   = (-1765328145);
pub const KRB5_EAI_NODATA: krb5_error_code                                 = (-1765328144);
pub const KRB5_EAI_NONAME: krb5_error_code                                 = (-1765328143);
pub const KRB5_EAI_SERVICE: krb5_error_code                                = (-1765328142);
pub const KRB5_ERR_NUMERIC_REALM: krb5_error_code                          = (-1765328141);
pub const KRB5_ERR_BAD_S2K_PARAMS: krb5_error_code                         = (-1765328140);
pub const KRB5_ERR_NO_SERVICE: krb5_error_code                             = (-1765328139);
pub const KRB5_CC_READONLY: krb5_error_code                                = (-1765328138);
pub const KRB5_CC_NOSUPP: krb5_error_code                                  = (-1765328137);
pub const KRB5_DELTAT_BADFORMAT: krb5_error_code                           = (-1765328136);
pub const KRB5_PLUGIN_NO_HANDLE: krb5_error_code                           = (-1765328135);
pub const KRB5_PLUGIN_OP_NOTSUPP: krb5_error_code                          = (-1765328134);
pub const KRB5_ERR_INVALID_UTF8: krb5_error_code                           = (-1765328133);
pub const KRB5_ERR_FAST_REQUIRED: krb5_error_code                          = (-1765328132);
pub const KRB5_LOCAL_ADDR_REQUIRED: krb5_error_code                        = (-1765328131);
pub const KRB5_REMOTE_ADDR_REQUIRED: krb5_error_code                       = (-1765328130);
pub const KRB5_TRACE_NOSUPP: krb5_error_code                               = (-1765328129);

// NOTE: from krb5/krb5.h : 8445
//       not quite sure how to translate this.
pub enum error_table {}
pub enum et_krb5_error_table {}

// TODO: not defined here. search where from!
pub enum et_list {}

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    // NOTE: also extern in header
    pub fn initialize_krb5_error_table();
    pub fn initialize_krb5_error_table_r(list: *mut *mut et_list);
}

pub const ERROR_TABLE_BASE_krb5: krb5_error_code = (-1765328384);

// TODO: Two defines here for compability with older versions

// include et/com_err.h

pub const KRB5_PLUGIN_VER_NOTSUPP: krb5_error_code     = (-1750600192);
pub const KRB5_PLUGIN_BAD_MODULE_SPEC: krb5_error_code = (-1750600191);
pub const KRB5_PLUGIN_NAME_NOTFOUND: krb5_error_code   = (-1750600190);
pub const KRB5KDC_ERR_DISCARD: krb5_error_code         = (-1750600189);
pub const KRB5_DCC_CANNOT_CREATE: krb5_error_code      = (-1750600188);
pub const KRB5_KCC_INVALID_ANCHOR: krb5_error_code     = (-1750600187);
pub const KRB5_KCC_UNKNOWN_VERSION: krb5_error_code    = (-1750600186);
pub const KRB5_KCC_INVALID_UID: krb5_error_code        = (-1750600185);
pub const KRB5_KCM_MALFORMED_REPLY: krb5_error_code    = (-1750600184);
pub const KRB5_KCM_RPC_ERROR: krb5_error_code          = (-1750600183);
pub const KRB5_KCM_REPLY_TOO_BIG: krb5_error_code      = (-1750600182);
pub const KRB5_KCM_NO_SERVER: krb5_error_code          = (-1750600181);

// extern const here

#[link(name = "krb5")]
extern "C" {
    // TODO: Doc
    // NOTE: Also extern in header
    pub fn initialize_k5e1_error_table();
    // TODO: Doc
    // NOTE: also extern in header
    pub fn initialize_k5e1_error_table_r(list: *mut *mut et_list);
}

pub const ERROR_TABLE_BASE_k5e1: krb5_error_code = (-1750600192);

// TODO: two defines for compability with older versions.

// TODO: include et/com_err.h

pub const KRB5_KDB_RCSID: krb5_error_code                  = (-1780008448);
pub const KRB5_KDB_INUSE: krb5_error_code                  = (-1780008447);
pub const KRB5_KDB_UK_SERROR: krb5_error_code              = (-1780008446);
pub const KRB5_KDB_UK_RERROR: krb5_error_code              = (-1780008445);
pub const KRB5_KDB_UNAUTH: krb5_error_code                 = (-1780008444);
pub const KRB5_KDB_NOENTRY: krb5_error_code                = (-1780008443);
pub const KRB5_KDB_ILL_WILDCARD: krb5_error_code           = (-1780008442);
pub const KRB5_KDB_DB_INUSE: krb5_error_code               = (-1780008441);
pub const KRB5_KDB_DB_CHANGED: krb5_error_code             = (-1780008440);
pub const KRB5_KDB_TRUNCATED_RECORD: krb5_error_code       = (-1780008439);
pub const KRB5_KDB_RECURSIVELOCK: krb5_error_code          = (-1780008438);
pub const KRB5_KDB_NOTLOCKED: krb5_error_code              = (-1780008437);
pub const KRB5_KDB_BADLOCKMODE: krb5_error_code            = (-1780008436);
pub const KRB5_KDB_DBNOTINITED: krb5_error_code            = (-1780008435);
pub const KRB5_KDB_DBINITED: krb5_error_code               = (-1780008434);
pub const KRB5_KDB_ILLDIRECTION: krb5_error_code           = (-1780008433);
pub const KRB5_KDB_NOMASTERKEY: krb5_error_code            = (-1780008432);
pub const KRB5_KDB_BADMASTERKEY: krb5_error_code           = (-1780008431);
pub const KRB5_KDB_INVALIDKEYSIZE: krb5_error_code         = (-1780008430);
pub const KRB5_KDB_CANTREAD_STORED: krb5_error_code        = (-1780008429);
pub const KRB5_KDB_BADSTORED_MKEY: krb5_error_code         = (-1780008428);
pub const KRB5_KDB_NOACTMASTERKEY: krb5_error_code         = (-1780008427);
pub const KRB5_KDB_KVNONOMATCH: krb5_error_code            = (-1780008426);
pub const KRB5_KDB_STORED_MKEY_NOTCURRENT: krb5_error_code = (-1780008425);
pub const KRB5_KDB_CANTLOCK_DB: krb5_error_code            = (-1780008424);
pub const KRB5_KDB_DB_CORRUPT: krb5_error_code             = (-1780008423);
pub const KRB5_KDB_BAD_VERSION: krb5_error_code            = (-1780008422);
pub const KRB5_KDB_BAD_SALTTYPE: krb5_error_code           = (-1780008421);
pub const KRB5_KDB_BAD_ENCTYPE: krb5_error_code            = (-1780008420);
pub const KRB5_KDB_BAD_CREATEFLAGS: krb5_error_code        = (-1780008419);
pub const KRB5_KDB_NO_PERMITTED_KEY: krb5_error_code       = (-1780008418);
pub const KRB5_KDB_NO_MATCHING_KEY: krb5_error_code        = (-1780008417);
pub const KRB5_KDB_DBTYPE_NOTFOUND: krb5_error_code        = (-1780008416);
pub const KRB5_KDB_DBTYPE_NOSUP: krb5_error_code           = (-1780008415);
pub const KRB5_KDB_DBTYPE_INIT: krb5_error_code            = (-1780008414);
pub const KRB5_KDB_SERVER_INTERNAL_ERR: krb5_error_code    = (-1780008413);
pub const KRB5_KDB_ACCESS_ERROR: krb5_error_code           = (-1780008412);
pub const KRB5_KDB_INTERNAL_ERROR: krb5_error_code         = (-1780008411);
pub const KRB5_KDB_CONSTRAINT_VIOLATION: krb5_error_code   = (-1780008410);
pub const KRB5_LOG_CONV: krb5_error_code                   = (-1780008409);
pub const KRB5_LOG_UNSTABLE: krb5_error_code               = (-1780008408);
pub const KRB5_LOG_CORRUPT: krb5_error_code                = (-1780008407);
pub const KRB5_LOG_ERROR: krb5_error_code                  = (-1780008406);
pub const KRB5_KDB_DBTYPE_MISMATCH: krb5_error_code        = (-1780008405);
pub const KRB5_KDB_POLICY_REF: krb5_error_code             = (-1780008404);
pub const KRB5_KDB_STRINGS_TOOLONG: krb5_error_code        = (-1780008403);

// TODO: extern const struct.

#[link(name = "krb5")]
extern "C" {
    // NOTE: also extern in header
    pub fn initialize_kdb5_error_table();
    // NOTE: also extern in header
    pub fn initialize_kdb5_error_table_r(list: *mut *mut et_list);
}

pub const ERROR_TABLE_BASE_kdb5: krb5_error_code = (-1780008448);

// TODO: two macros for compability with older versions

// TODO: include et/com_err.h

pub const KV5M_NONE: krb5_error_code                   = (-1760647424);
pub const KV5M_PRINCIPAL: krb5_error_code              = (-1760647423);
pub const KV5M_DATA: krb5_error_code                   = (-1760647422);
pub const KV5M_KEYBLOCK: krb5_error_code               = (-1760647421);
pub const KV5M_CHECKSUM: krb5_error_code               = (-1760647420);
pub const KV5M_ENCRYPT_BLOCK: krb5_error_code          = (-1760647419);
pub const KV5M_ENC_DATA: krb5_error_code               = (-1760647418);
pub const KV5M_CRYPTOSYSTEM_ENTRY: krb5_error_code     = (-1760647417);
pub const KV5M_CS_TABLE_ENTRY: krb5_error_code         = (-1760647416);
pub const KV5M_CHECKSUM_ENTRY: krb5_error_code         = (-1760647415);
pub const KV5M_AUTHDATA: krb5_error_code               = (-1760647414);
pub const KV5M_TRANSITED: krb5_error_code              = (-1760647413);
pub const KV5M_ENC_TKT_PART: krb5_error_code           = (-1760647412);
pub const KV5M_TICKET: krb5_error_code                 = (-1760647411);
pub const KV5M_AUTHENTICATOR: krb5_error_code          = (-1760647410);
pub const KV5M_TKT_AUTHENT: krb5_error_code            = (-1760647409);
pub const KV5M_CREDS: krb5_error_code                  = (-1760647408);
pub const KV5M_LAST_REQ_ENTRY: krb5_error_code         = (-1760647407);
pub const KV5M_PA_DATA: krb5_error_code                = (-1760647406);
pub const KV5M_KDC_REQ: krb5_error_code                = (-1760647405);
pub const KV5M_ENC_KDC_REP_PART: krb5_error_code       = (-1760647404);
pub const KV5M_KDC_REP: krb5_error_code                = (-1760647403);
pub const KV5M_ERROR: krb5_error_code                  = (-1760647402);
pub const KV5M_AP_REQ: krb5_error_code                 = (-1760647401);
pub const KV5M_AP_REP: krb5_error_code                 = (-1760647400);
pub const KV5M_AP_REP_ENC_PART: krb5_error_code        = (-1760647399);
pub const KV5M_RESPONSE: krb5_error_code               = (-1760647398);
pub const KV5M_SAFE: krb5_error_code                   = (-1760647397);
pub const KV5M_PRIV: krb5_error_code                   = (-1760647396);
pub const KV5M_PRIV_ENC_PART: krb5_error_code          = (-1760647395);
pub const KV5M_CRED: krb5_error_code                   = (-1760647394);
pub const KV5M_CRED_INFO: krb5_error_code              = (-1760647393);
pub const KV5M_CRED_ENC_PART: krb5_error_code          = (-1760647392);
pub const KV5M_PWD_DATA: krb5_error_code               = (-1760647391);
pub const KV5M_ADDRESS: krb5_error_code                = (-1760647390);
pub const KV5M_KEYTAB_ENTRY: krb5_error_code           = (-1760647389);
pub const KV5M_CONTEXT: krb5_error_code                = (-1760647388);
pub const KV5M_OS_CONTEXT: krb5_error_code             = (-1760647387);
pub const KV5M_ALT_METHOD: krb5_error_code             = (-1760647386);
pub const KV5M_ETYPE_INFO_ENTRY: krb5_error_code       = (-1760647385);
pub const KV5M_DB_CONTEXT: krb5_error_code             = (-1760647384);
pub const KV5M_AUTH_CONTEXT: krb5_error_code           = (-1760647383);
pub const KV5M_KEYTAB: krb5_error_code                 = (-1760647382);
pub const KV5M_RCACHE: krb5_error_code                 = (-1760647381);
pub const KV5M_CCACHE: krb5_error_code                 = (-1760647380);
pub const KV5M_PREAUTH_OPS: krb5_error_code            = (-1760647379);
pub const KV5M_SAM_CHALLENGE: krb5_error_code          = (-1760647378);
pub const KV5M_SAM_CHALLENGE_2: krb5_error_code        = (-1760647377);
pub const KV5M_SAM_KEY: krb5_error_code                = (-1760647376);
pub const KV5M_ENC_SAM_RESPONSE_ENC: krb5_error_code   = (-1760647375);
pub const KV5M_ENC_SAM_RESPONSE_ENC_2: krb5_error_code = (-1760647374);
pub const KV5M_SAM_RESPONSE: krb5_error_code           = (-1760647373);
pub const KV5M_SAM_RESPONSE_2: krb5_error_code         = (-1760647372);
pub const KV5M_PREDICTED_SAM_RESPONSE: krb5_error_code = (-1760647371);
pub const KV5M_PASSWD_PHRASE_ELEMENT: krb5_error_code  = (-1760647370);
pub const KV5M_GSS_OID: krb5_error_code                = (-1760647369);
pub const KV5M_GSS_QUEUE: krb5_error_code              = (-1760647368);
pub const KV5M_FAST_ARMORED_REQ: krb5_error_code       = (-1760647367);
pub const KV5M_FAST_REQ: krb5_error_code               = (-1760647366);
pub const KV5M_FAST_RESPONSE: krb5_error_code          = (-1760647365);
pub const KV5M_AUTHDATA_CONTEXT: krb5_error_code       = (-1760647364);
// TODO: extern const here

#[link(name = "krb5")]
extern "C" {
    // NOTE: also extern in the header
    pub fn initialize_kv5m_error_table();
    // NOTE: also extern in the header
    pub fn initialize_kv5m_error_table_r(list: *mut *mut et_list);
}

pub const ERROR_TABLE_BASE_kv5m: krb5_error_code = (-1760647424);

// TODO: Two macros for compability with older versions

// TODO: include et/com_err.h

pub const KRB524_BADKEY: krb5_error_code        = (-1750206208);
pub const KRB524_BADADDR: krb5_error_code       = (-1750206207);
pub const KRB524_BADPRINC: krb5_error_code      = (-1750206206);
pub const KRB524_BADREALM: krb5_error_code      = (-1750206205);
pub const KRB524_V4ERR: krb5_error_code         = (-1750206204);
pub const KRB524_ENCFULL: krb5_error_code       = (-1750206203);
pub const KRB524_DECEMPTY: krb5_error_code      = (-1750206202);
pub const KRB524_NOTRESP: krb5_error_code       = (-1750206201);
pub const KRB524_KRB4_DISABLED: krb5_error_code = (-1750206200);
// TODO extern const here

#[link(name = "krb5")]
extern "C" {
    // NOTE: also extern in header
    pub fn initialize_k524_error_table();
    // NOTE: also extern in header
    pub fn initialize_k524_error_table_r(list: *mut *mut et_list);
}

pub const ERROR_TABLE_BASE_k524: krb5_error_code = (-1750206208);

// TODO: two macros for compability with older versions

// TODO: include et/com_err.h


pub const ASN1_BAD_TIMEFORMAT: krb5_error_code  = (1859794432);
pub const ASN1_MISSING_FIELD: krb5_error_code   = (1859794433);
pub const ASN1_MISPLACED_FIELD: krb5_error_code = (1859794434);
pub const ASN1_TYPE_MISMATCH: krb5_error_code   = (1859794435);
pub const ASN1_OVERFLOW: krb5_error_code        = (1859794436);
pub const ASN1_OVERRUN: krb5_error_code         = (1859794437);
pub const ASN1_BAD_ID: krb5_error_code          = (1859794438);
pub const ASN1_BAD_LENGTH: krb5_error_code      = (1859794439);
pub const ASN1_BAD_FORMAT: krb5_error_code      = (1859794440);
pub const ASN1_PARSE_ERROR: krb5_error_code     = (1859794441);
pub const ASN1_BAD_GMTIME: krb5_error_code      = (1859794442);
pub const ASN1_MISMATCH_INDEF: krb5_error_code  = (1859794443);
pub const ASN1_MISSING_EOC: krb5_error_code     = (1859794444);
pub const ASN1_OMITTED: krb5_error_code         = (1859794445);
// TODO: extern const here..

#[link(name = "krb5")]
extern "C" {
    // NOTE: also extern in header
    pub fn initlialize_asn1_error_table();
    // NOTE: also extern in header
    pub fn initlialize_asn1_error_table_r(list: *mut *mut et_list);
}

pub const ERROR_TABLE_BASE_asn1: krb5_error_code = (1859794432);

// TODO: two macros for compatibility with older versions
#[cfg(test)]
mod test_nullable_callbacks {
    use std::ptr;
    use std::os::raw::*;
    use crate as k5;

    #[test]
    fn test_checksum_fn_set_get_null() {
        let mut ctx : k5::krb5_context = ptr::null_mut();
        let mut actx: k5::krb5_auth_context = ptr::null_mut();

        assert_eq!(0, unsafe {
            k5::krb5_init_context(&mut ctx)
        });

        assert_eq!(0, unsafe {
            k5::krb5_auth_con_init(ctx, &mut actx)
        });

        /* Erase callback. */
        assert_eq!(0, unsafe {
            k5::krb5_auth_con_set_checksum_func
                (ctx, actx, None, ptr::null_mut())
        });

        let mut dst_func: Option<k5::krb5_mk_req_checksum_func> = None;
        let mut dst_data: *mut c_void = ptr::null_mut();

        /* Retrieve callback; result should be None. */
        assert_eq!(0, unsafe {
            k5::krb5_auth_con_get_checksum_func
                (ctx, actx, &mut dst_func, &mut dst_data)
        });

        assert_eq!(dst_func, None);
        assert_eq!(dst_data, ptr::null_mut());

        assert_eq!(0, unsafe { k5::krb5_auth_con_free(ctx, actx) });

        unsafe { k5::krb5_free_context(ctx) };
    }

    #[test]
    fn test_responder_fn_set_null() {
        let mut ctx : k5::krb5_context = ptr::null_mut();

        assert_eq!(0, unsafe {
            k5::krb5_init_context(&mut ctx)
        });

        let mut opts: *mut k5::krb5_get_init_creds_opt = ptr::null_mut();

        assert_eq!(0, unsafe {
            k5::krb5_get_init_creds_opt_alloc(ctx, &mut opts)
        });

        /* Erase callback. */
        assert_eq!(0, unsafe {
            k5::krb5_get_init_creds_opt_set_responder
                (ctx, opts, None, ptr::null_mut())
        });

        unsafe { k5::krb5_get_init_creds_opt_free(ctx, opts) };

        unsafe { k5::krb5_free_context(ctx) };
    }

    /* Test ignored by default as it will normally cause a contacting a
       non-existent KDC or another error. */
    #[ignore]
    #[test]
    fn test_prompter_fn_set_null() {
        let mut ctx : k5::krb5_context = ptr::null_mut();

        assert_eq!(0, unsafe {
            k5::krb5_init_context(&mut ctx)
        });

        let mut creds: k5::krb5_creds = unsafe {
            std::mem::MaybeUninit::zeroed().assume_init()
        };

        let name: &'static [u8] = b"test\0";
        let mut princ: k5::krb5_principal = ptr::null_mut();

        assert_eq!(0, unsafe {
            k5::krb5_parse_name(ctx, name.as_ptr() as *const c_char, &mut princ)
        });

        /* Call without password and with a null callback; this operation
           is expected to fail. The test is considered successful if below
           call does not segfault on account of a null pointer dereference. */
        assert_ne!(0, unsafe {
            k5::krb5_get_init_creds_password
                (ctx,
                 &mut creds,
                 princ,
                 ptr::null(),       /* don't set password -> use prompter */
                 None,              /* unset prompter callback */
                 ptr::null_mut(),
                 0,
                 ptr::null(),
                 ptr::null())
        });

        unsafe { k5::krb5_free_principal(ctx, princ) };
        unsafe { k5::krb5_free_context(ctx) };
    }

    #[test]
    fn test_trace_fn_set_null() {
        let mut ctx : k5::krb5_context = ptr::null_mut();

        assert_eq!(0, unsafe {
            k5::krb5_init_context(&mut ctx)
        });

        /* Erase callback. */
        assert_eq!(0, unsafe {
            k5::krb5_set_trace_callback
                (ctx, None, ptr::null_mut())
        });

        unsafe { k5::krb5_free_context(ctx) };
    }
}

