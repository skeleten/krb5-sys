use ::std::os::raw::c_int;
use ::{krb5_context,
       krb5_error_code};

// TODO: Doc
pub enum krb5_plugin_vtable_st { }
pub type krb5_plugin_vtable = *mut krb5_plugin_vtable_st;

// TODO: Doc
pub type krb5_plugin_initvt_fn = extern "C" fn(context: krb5_context,
                                               maj_ver: c_int,
                                               min_ver: c_int,
                                               vtable: krb5_plugin_vtable) -> krb5_error_code;
