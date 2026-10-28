//! Composed mechanisms through the `extern "C"` functions.

use cryptoki_sys::{
    CKF_EC_F_P, CKF_EC_NAMEDCURVE, CKF_SIGN, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512,
    CKM_SHA256, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CKR_OK,
};

use super::*;

#[test]
fn composed_mechanism_info() {
    let s = Session::new();
    s.open();
    let mut info = std::mem::MaybeUninit::<CK_MECHANISM_INFO>::zeroed();
    // SAFETY: `info` is a live local.
    unsafe {
        for m in [CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512] {
            assert_eq!(C_GetMechanismInfo(0, m, info.as_mut_ptr()), CKR_OK);
            let i = info.assume_init_ref();
            assert_eq!(i.flags, CKF_SIGN | CKF_EC_F_P | CKF_EC_NAMEDCURVE);
            assert_eq!((i.ulMinKeySize, i.ulMaxKeySize), (256, 256));
        }
        for m in [
            CKM_SHA256_RSA_PKCS,
            CKM_SHA384_RSA_PKCS,
            CKM_SHA512_RSA_PKCS,
        ] {
            assert_eq!(
                C_GetMechanismInfo(0, m, info.as_mut_ptr()),
                CKR_MECHANISM_INVALID
            );
        }
    }
}

#[test]
fn composed_sign_init_parameter() {
    let s = Session::new();
    let session = s.open();
    let mut byte = 0_u8;
    let pss = CK_RSA_PKCS_PSS_PARAMS {
        hashAlg: CKM_SHA256,
        mgf: cryptoki_sys::CKG_MGF1_SHA256,
        sLen: 32,
    };
    let mut pss = pss;
    // SAFETY: pointers are to live locals; sizes passed are the real ones.
    unsafe {
        for ckm in [CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512] {
            let mut with_pointer = mechanism(ckm, (&raw mut byte).cast(), 0);
            let mut with_length = mechanism(ckm, ptr::null_mut(), 1);
            let mut with_pss = mechanism(
                ckm,
                (&raw mut pss).cast(),
                size_of::<CK_RSA_PKCS_PSS_PARAMS>() as CK_ULONG,
            );
            for m in [&mut with_pointer, &mut with_length, &mut with_pss] {
                assert_eq!(C_SignInit(session, m, 2), CKR_MECHANISM_PARAM_INVALID);
            }
            // The refused ininits left no operation active.
            let mut plain = mechanism(ckm, ptr::null_mut(), 0);
            assert_eq!(C_SignInit(session, &raw mut plain, 2), CKR_OK);
            let mut len: CK_ULONG = 0;
            assert_eq!(
                C_Sign(session, &raw mut byte, 1, ptr::null_mut(), &raw mut len),
                CKR_OK
            );
            assert_eq!(len, 64);
            let mut sig = [0_u8; 64];
            assert_eq!(
                C_Sign(session, &raw mut byte, 1, sig.as_mut_ptr(), &raw mut len),
                CKR_OK
            );
        }
    }
}
