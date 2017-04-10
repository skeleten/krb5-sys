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

pub enum _krb5_context {}
pub type krb5_context = *mut _krb5_context;

pub enum _krb5_auth_context {}
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

extern {
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

extern {
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

extern {
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

pub const KDC_OPT_FORWARDABLE: u32             = 0x40000000;
pub const KDC_OPT_FORWARDED: u32               = 0x20000000;
pub const KDC_OPT_PROXIABLE: u32               = 0x10000000;
pub const KDC_OPT_PROXY: u32                   = 0x08000000;
pub const KDC_OPT_ALLOW_POSTDATED: u32         = 0x04000000;
pub const KDC_OPT_POSTDATED: u32               = 0x02000000;

pub const KDC_OPT_RENEWABLE: u32               = 0x00800000;

pub const KDC_OPT_CNAME_IN_ADDL_TKT: u32       = 0x00020000;
pub const KDC_OPT_CANONICALIZE: u32            = 0x00010000;
pub const KDC_OPT_REQUEST_ANONYMOUS: u32       = 0x00008000;

pub const KDC_OPT_DISABLE_TRANSITED_CHEDK: u32 = 0x00000020;
pub const KDC_OPT_RENEWABLE_OK: u32            = 0x00000010;
pub const KDC_OPT_ENC_TKT_IN_SKEY: u32         = 0x00000008;

pub const KDC_OPT_RENEW: u32                   = 0x00000002;
pub const KDC_OPT_VALIDATE: u32                = 0x00000001;

pub const KDC_TKT_COMMON_MASK: u32             = 0x54800000;

pub const AP_OPTS_RESERVERD: u32               = 0x80000000;
/// Use session key
pub const AP_OPTS_USE_SESSION_KEY: u32         = 0x40000000;
/// Perform a mutual authentiction exchange
pub const AP_OPTS_MUTUAL_REQUIRED: u32         = 0x20000000;

pub const AP_OPTS_ETYPE_NEGOTIATION: u32       = 0x00000002;
/// Generate a subsession key from the curretn session key obtained from
/// the credentials
pub const AP_OPTS_USE_SUBKEY: u32              = 0x00000001;

pub const AP_OPTS_WIRE_MASK: u32               = 0xfffffff0;

pub const AD_TYPE_RESERVED: u16                = 0x8000;
pub const AD_TYPE_EXTERNAL: u16                = 0x4000;
pub const AD_TYPE_REGISTERED: u16              = 0x2000;

pub const AD_TYPE_FIELD_TYPE_MASK: u16         = 0x1fff;

pub const TKT_FLG_FORWARDABLE: u32             = 0x40000000;
pub const TKT_FLG_FORWARDED: u32               = 0x20000000;
pub const TKT_FLG_PROXIABLE: u32               = 0x10000000;
pub const TKT_FLG_PROXY: u32                   = 0x08000000;
pub const TKT_FLG_MAY_POSTDATE: u32            = 0x04000000;
pub const TKT_FLG_POSTDATED: u32               = 0x02000000;
pub const TKT_FLG_INVALID: u32                 = 0x01000000;
pub const TKT_FLG_RENEWABLE: u32               = 0x00800000;
pub const TKT_FLG_INITIAL: u32                 = 0x00400000;
pub const TKT_FLG_PRE_AUTH: u32                = 0x00200000;
pub const TKT_FLG_HW_AUTH: u32                 = 0x00100000;
pub const TKT_FLG_TRANSIT_POLICY_CHECKED: u32  = 0x00080000;
pub const TKT_FLG_OK_AS_DELEGATE: u32          = 0x00040000;
pub const TKT_FLG_ENC_PA_REP: u32              = 0x00010000;
pub const TKT_FLG_ANONYMOUS: u32               = 0x00008000;

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
