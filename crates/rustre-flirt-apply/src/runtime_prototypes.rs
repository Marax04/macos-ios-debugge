//! Runtime prototypes for the mingw-w64 / libgcc functions the corpus contains.
//!
//! **GENERATED FILE — do not edit by hand.**
//! Regenerate with `python tools/gen_runtime_prototypes.py`.
//!
//! Every entry is extracted mechanically from an installed header, with the
//! header name and line recorded beside it. Prototypes are never written from
//! memory: a subtly wrong one compiles cleanly and then corrupts the recovered
//! types of every caller, which is strictly worse than having no prototype.
//!
//! Variadic functions are omitted on purpose — an emitted fixed-arity signature
//! cannot match `...`, so publishing one would assert something false.

use crate::rename_propagator::{FunctionSignature, TypeDescriptor};

/// All prototypes extracted from the installed mingw-w64 / libgcc headers.
#[must_use]
pub fn runtime_prototypes() -> Vec<FunctionSignature> {
    let mut all = Vec::new();
    all.extend(runtime_prototypes_part_0());
    all.extend(runtime_prototypes_part_1());
    all.extend(runtime_prototypes_part_2());
    all.extend(runtime_prototypes_part_3());
    all.extend(runtime_prototypes_part_4());
    all.extend(runtime_prototypes_part_5());
    all.extend(runtime_prototypes_part_6());
    all.extend(runtime_prototypes_part_7());
    all.extend(runtime_prototypes_part_8());
    all.extend(runtime_prototypes_part_9());
    all.extend(runtime_prototypes_part_10());
    all.extend(runtime_prototypes_part_11());
    all
}

/// Prototypes 0..12 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_0() -> Vec<FunctionSignature> {
    vec![
        // unwind.h:120
        FunctionSignature {
            name: "_Unwind_Backtrace".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Reason_Code".into()),
            params: vec![("arg0".into(), TypeDescriptor::Struct("_Unwind_Trace_Fn".into())), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Void)))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:106
        FunctionSignature {
            name: "_Unwind_DeleteException".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:183
        FunctionSignature {
            name: "_Unwind_FindEnclosingFunction".into(),
            return_type: TypeDescriptor::Pointer(Box::new(TypeDescriptor::Void)),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void pc".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:102
        FunctionSignature {
            name: "_Unwind_ForcedUnwind".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Reason_Code".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into())))), ("arg1".into(), TypeDescriptor::Struct("_Unwind_Stop_Fn".into())), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Void)))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:179
        FunctionSignature {
            name: "_Unwind_GetBSP".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Word".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:133
        FunctionSignature {
            name: "_Unwind_GetCFA".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Word".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:180
        FunctionSignature {
            name: "_Unwind_GetDataRelBase".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Ptr".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:125
        FunctionSignature {
            name: "_Unwind_GetGR".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Word".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into())))), ("arg1".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:128
        FunctionSignature {
            name: "_Unwind_GetIP".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Ptr".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:129
        FunctionSignature {
            name: "_Unwind_GetIPInfo".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Ptr".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::I32)))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:135
        FunctionSignature {
            name: "_Unwind_GetLanguageSpecificData".into(),
            return_type: TypeDescriptor::Pointer(Box::new(TypeDescriptor::Void)),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:137
        FunctionSignature {
            name: "_Unwind_GetRegionStart".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Ptr".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 12..24 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_1() -> Vec<FunctionSignature> {
    vec![
        // unwind.h:182
        FunctionSignature {
            name: "_Unwind_GetTextRelBase".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Ptr".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:93
        FunctionSignature {
            name: "_Unwind_RaiseException".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Reason_Code".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:109
        FunctionSignature {
            name: "_Unwind_Resume".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:113
        FunctionSignature {
            name: "_Unwind_Resume_or_Rethrow".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Reason_Code".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:126
        FunctionSignature {
            name: "_Unwind_SetGR".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into())))), ("arg1".into(), TypeDescriptor::I32), ("arg2".into(), TypeDescriptor::Struct("_Unwind_Word".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:130
        FunctionSignature {
            name: "_Unwind_SetIP".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Context".into())))), ("arg1".into(), TypeDescriptor::Struct("_Unwind_Ptr".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:154
        FunctionSignature {
            name: "_Unwind_SjLj_ForcedUnwind".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Reason_Code".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into())))), ("arg1".into(), TypeDescriptor::Struct("_Unwind_Stop_Fn".into())), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Void)))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:152
        FunctionSignature {
            name: "_Unwind_SjLj_RaiseException".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Reason_Code".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:149
        FunctionSignature {
            name: "_Unwind_SjLj_Register".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("SjLj_Function_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:156
        FunctionSignature {
            name: "_Unwind_SjLj_Resume".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:158
        FunctionSignature {
            name: "_Unwind_SjLj_Resume_or_Rethrow".into(),
            return_type: TypeDescriptor::Struct("_Unwind_Reason_Code".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_Unwind_Exception".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // unwind.h:150
        FunctionSignature {
            name: "_Unwind_SjLj_Unregister".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("SjLj_Function_Context".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 24..36 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_2() -> Vec<FunctionSignature> {
    vec![
        // wchar.h:55
        FunctionSignature {
            name: "__acrt_iob_func".into(),
            return_type: TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("FILE".into()))),
            params: vec![("index".into(), TypeDescriptor::U32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // math.h:160
        FunctionSignature {
            name: "__mingw_raise_matherr".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("typ".into(), TypeDescriptor::I32), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("char name".into())))), ("a1".into(), TypeDescriptor::F64), ("a2".into(), TypeDescriptor::F64), ("rslt".into(), TypeDescriptor::F64)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // assert.h:19
        FunctionSignature {
            name: "_assert".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("char _Message".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("char _File".into())))), ("_Line".into(), TypeDescriptor::U32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // locale.h:83
        FunctionSignature {
            name: "_configthreadlocale".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("_Flag".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // math.h:278
        FunctionSignature {
            name: "_matherr".into(),
            return_type: TypeDescriptor::Struct("define _CRT_MATHERR_DEFINED int".into()),
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_exception".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:206
        FunctionSignature {
            name: "_pthread_cleanup_dest".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("t".into(), TypeDescriptor::Struct("pthread_t".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:213
        FunctionSignature {
            name: "_pthread_get_state".into(),
            return_type: TypeDescriptor::U32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("flag".into(), TypeDescriptor::U32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:210
        FunctionSignature {
            name: "_pthread_invoke_cancel".into(),
            return_type: TypeDescriptor::Void,
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:214
        FunctionSignature {
            name: "_pthread_set_state".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("flag".into(), TypeDescriptor::U32), ("val".into(), TypeDescriptor::U32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:353
        FunctionSignature {
            name: "_pthread_tryjoin".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("t".into(), TypeDescriptor::Struct("pthread_t".into())), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void res".into()))))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // wchar.h:1203
        FunctionSignature {
            name: "mbrtowc".into(),
            return_type: TypeDescriptor::U64,
            params: vec![("_DstCh".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("wchar_t __".into())))), ("_SrcCh".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("char __".into())))), ("_SizeInBytes".into(), TypeDescriptor::U64), ("_State".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("mbstate_t __".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:306
        FunctionSignature {
            name: "pthread_attr_destroy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 36..48 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_3() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:308
        FunctionSignature {
            name: "pthread_attr_getdetachstate".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t a".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int flag".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:310
        FunctionSignature {
            name: "pthread_attr_getinheritsched".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t a".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int flag".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:165
        FunctionSignature {
            name: "pthread_attr_getschedparam".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("sched_param param".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:169
        FunctionSignature {
            name: "pthread_attr_getschedpolicy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int pol".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:312
        FunctionSignature {
            name: "pthread_attr_getscope".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t a".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int flag".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:313
        FunctionSignature {
            name: "pthread_attr_getstack".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void stack".into())))))), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("size_t size".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:315
        FunctionSignature {
            name: "pthread_attr_getstackaddr".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void stack".into()))))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:317
        FunctionSignature {
            name: "pthread_attr_getstacksize".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("size_t size".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:305
        FunctionSignature {
            name: "pthread_attr_init".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:307
        FunctionSignature {
            name: "pthread_attr_setdetachstate".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t a".into())))), ("flag".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:309
        FunctionSignature {
            name: "pthread_attr_setinheritsched".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t a".into())))), ("flag".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:164
        FunctionSignature {
            name: "pthread_attr_setschedparam".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("sched_param param".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 48..60 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_4() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:168
        FunctionSignature {
            name: "pthread_attr_setschedpolicy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("pol".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:311
        FunctionSignature {
            name: "pthread_attr_setscope".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t a".into())))), ("flag".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:314
        FunctionSignature {
            name: "pthread_attr_setstack".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void stack".into())))), ("size".into(), TypeDescriptor::U64)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:316
        FunctionSignature {
            name: "pthread_attr_setstackaddr".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void stack".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:318
        FunctionSignature {
            name: "pthread_attr_setstacksize".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_attr_t attr".into())))), ("size".into(), TypeDescriptor::U64)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:211
        FunctionSignature {
            name: "pthread_cancel".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("t".into(), TypeDescriptor::Struct("pthread_t".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:255
        FunctionSignature {
            name: "pthread_cond_broadcast".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:253
        FunctionSignature {
            name: "pthread_cond_destroy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:252
        FunctionSignature {
            name: "pthread_cond_init".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_condattr_t a".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:254
        FunctionSignature {
            name: "pthread_cond_signal".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:257
        FunctionSignature {
            name: "pthread_cond_timedwait32".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t external_mutex".into())))), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec32 t".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:267
        FunctionSignature {
            name: "pthread_cond_timedwait32_relative_np".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t external_mutex".into())))), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec32 t".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 60..72 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_5() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:258
        FunctionSignature {
            name: "pthread_cond_timedwait64".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t external_mutex".into())))), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec64 t".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:268
        FunctionSignature {
            name: "pthread_cond_timedwait64_relative_np".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t external_mutex".into())))), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec64 t".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:256
        FunctionSignature {
            name: "pthread_cond_wait".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_cond_t cv".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t external_mutex".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:333
        FunctionSignature {
            name: "pthread_condattr_destroy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_condattr_t a".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:338
        FunctionSignature {
            name: "pthread_condattr_getclock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_condattr_t attr".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("clockid_t clock_id".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:335
        FunctionSignature {
            name: "pthread_condattr_getpshared".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_condattr_t a".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int s".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:334
        FunctionSignature {
            name: "pthread_condattr_init".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_condattr_t a".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:340
        FunctionSignature {
            name: "pthread_condattr_setclock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_condattr_t attr".into())))), ("clock_id".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:336
        FunctionSignature {
            name: "pthread_condattr_setpshared".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_condattr_t a".into())))), ("s".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:217
        FunctionSignature {
            name: "pthread_create_wrapper".into(),
            return_type: TypeDescriptor::U32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void args".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:87
        FunctionSignature {
            name: "pthread_delay32_np".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec32 interval".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:88
        FunctionSignature {
            name: "pthread_delay64_np".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec64 interval".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 72..84 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_6() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:220
        FunctionSignature {
            name: "pthread_detach".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("t".into(), TypeDescriptor::Struct("pthread_t".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:204
        FunctionSignature {
            name: "pthread_equal".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("t1".into(), TypeDescriptor::Struct("pthread_t".into())), ("t2".into(), TypeDescriptor::Struct("pthread_t".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:209
        FunctionSignature {
            name: "pthread_exit".into(),
            return_type: TypeDescriptor::Void,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void res".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:207
        FunctionSignature {
            name: "pthread_get_concurrency".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int val".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:349
        FunctionSignature {
            name: "pthread_getclean".into(),
            return_type: TypeDescriptor::Pointer(Box::new(TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_pthread_cleanup".into()))))),
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:330
        FunctionSignature {
            name: "pthread_getconcurrency".into(),
            return_type: TypeDescriptor::I32,
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:351
        FunctionSignature {
            name: "pthread_getevent".into(),
            return_type: TypeDescriptor::Pointer(Box::new(TypeDescriptor::Void)),
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:350
        FunctionSignature {
            name: "pthread_gethandle".into(),
            return_type: TypeDescriptor::Pointer(Box::new(TypeDescriptor::Void)),
            params: vec![("t".into(), TypeDescriptor::Struct("pthread_t".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:222
        FunctionSignature {
            name: "pthread_getname_np".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("thread".into(), TypeDescriptor::Struct("pthread_t".into())), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("char name".into())))), ("len".into(), TypeDescriptor::U64)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:166
        FunctionSignature {
            name: "pthread_getschedparam".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("thread".into(), TypeDescriptor::Struct("pthread_t".into())), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int pol".into())))), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("sched_param param".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:198
        FunctionSignature {
            name: "pthread_getspecific".into(),
            return_type: TypeDescriptor::Pointer(Box::new(TypeDescriptor::Void)),
            params: vec![("key".into(), TypeDescriptor::Struct("pthread_key_t".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:219
        FunctionSignature {
            name: "pthread_join".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("t".into(), TypeDescriptor::Struct("pthread_t".into())), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void res".into()))))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 84..96 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_7() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:197
        FunctionSignature {
            name: "pthread_key_delete".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("key".into(), TypeDescriptor::Struct("pthread_key_t".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:212
        FunctionSignature {
            name: "pthread_kill".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("t".into(), TypeDescriptor::Struct("pthread_t".into())), ("sig".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:292
        FunctionSignature {
            name: "pthread_mutex_destroy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t m".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:291
        FunctionSignature {
            name: "pthread_mutex_init".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t m".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:278
        FunctionSignature {
            name: "pthread_mutex_lock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t m".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:279
        FunctionSignature {
            name: "pthread_mutex_timedlock32".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t m".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec32 ts".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:280
        FunctionSignature {
            name: "pthread_mutex_timedlock64".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t m".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec64 ts".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:290
        FunctionSignature {
            name: "pthread_mutex_trylock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t m".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:289
        FunctionSignature {
            name: "pthread_mutex_unlock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutex_t m".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:321
        FunctionSignature {
            name: "pthread_mutexattr_destroy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:328
        FunctionSignature {
            name: "pthread_mutexattr_getprioceiling".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into())))), ("prio".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::I32)))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:326
        FunctionSignature {
            name: "pthread_mutexattr_getprotocol".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int type".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 96..108 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_8() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:324
        FunctionSignature {
            name: "pthread_mutexattr_getpshared".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int type".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:322
        FunctionSignature {
            name: "pthread_mutexattr_gettype".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int type".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:320
        FunctionSignature {
            name: "pthread_mutexattr_init".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:329
        FunctionSignature {
            name: "pthread_mutexattr_setprioceiling".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into())))), ("prio".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:327
        FunctionSignature {
            name: "pthread_mutexattr_setprotocol".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into())))), ("type".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:325
        FunctionSignature {
            name: "pthread_mutexattr_setpshared".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("a".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t".into())))), ("type".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:323
        FunctionSignature {
            name: "pthread_mutexattr_settype".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_mutexattr_t a".into())))), ("type".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:97
        FunctionSignature {
            name: "pthread_num_processors_np".into(),
            return_type: TypeDescriptor::I32,
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:250
        FunctionSignature {
            name: "pthread_rwlock_destroy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:224
        FunctionSignature {
            name: "pthread_rwlock_init".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t rwlock_".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlockattr_t attr".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:236
        FunctionSignature {
            name: "pthread_rwlock_rdlock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:237
        FunctionSignature {
            name: "pthread_rwlock_timedrdlock32".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t l".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec32 ts".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 108..120 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_9() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:238
        FunctionSignature {
            name: "pthread_rwlock_timedrdlock64".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t l".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec64 ts".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:226
        FunctionSignature {
            name: "pthread_rwlock_timedwrlock32".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t rwlock".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec32 ts".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:227
        FunctionSignature {
            name: "pthread_rwlock_timedwrlock64".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t rwlock".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("_timespec64 ts".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:248
        FunctionSignature {
            name: "pthread_rwlock_tryrdlock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:249
        FunctionSignature {
            name: "pthread_rwlock_trywrlock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:247
        FunctionSignature {
            name: "pthread_rwlock_unlock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:225
        FunctionSignature {
            name: "pthread_rwlock_wrlock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:354
        FunctionSignature {
            name: "pthread_rwlockattr_destroy".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlockattr_t a".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:355
        FunctionSignature {
            name: "pthread_rwlockattr_getpshared".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlockattr_t a".into())))), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int s".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:356
        FunctionSignature {
            name: "pthread_rwlockattr_init".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlockattr_t a".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:357
        FunctionSignature {
            name: "pthread_rwlockattr_setpshared".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_rwlockattr_t a".into())))), ("s".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:201
        FunctionSignature {
            name: "pthread_self".into(),
            return_type: TypeDescriptor::Struct("pthread_t".into()),
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 120..132 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_10() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:208
        FunctionSignature {
            name: "pthread_set_concurrency".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("val".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:98
        FunctionSignature {
            name: "pthread_set_num_processors_np".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("n".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:215
        FunctionSignature {
            name: "pthread_setcancelstate".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("state".into(), TypeDescriptor::I32), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int oldstate".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:216
        FunctionSignature {
            name: "pthread_setcanceltype".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("type".into(), TypeDescriptor::I32), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("int oldtype".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:331
        FunctionSignature {
            name: "pthread_setconcurrency".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("new_level".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:221
        FunctionSignature {
            name: "pthread_setname_np".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("thread".into(), TypeDescriptor::Struct("pthread_t".into())), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("char name".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:167
        FunctionSignature {
            name: "pthread_setschedparam".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("thread".into(), TypeDescriptor::Struct("pthread_t".into())), ("pol".into(), TypeDescriptor::I32), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("sched_param param".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:199
        FunctionSignature {
            name: "pthread_setspecific".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("key".into(), TypeDescriptor::Struct("pthread_key_t".into())), ("arg1".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("void value".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:298
        FunctionSignature {
            name: "pthread_spin_init".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_spinlock_t l".into())))), ("pshared".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:301
        FunctionSignature {
            name: "pthread_spin_lock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_spinlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:302
        FunctionSignature {
            name: "pthread_spin_trylock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_spinlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:303
        FunctionSignature {
            name: "pthread_spin_unlock".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("arg0".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("pthread_spinlock_t l".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}

/// Prototypes 132..139 of the extracted table.
///
/// Decides nothing: it is one slice of a single generated list, split so no
/// one function has to carry the whole table.
fn runtime_prototypes_part_11() -> Vec<FunctionSignature> {
    vec![
        // pthread.h:203
        FunctionSignature {
            name: "pthread_testcancel".into(),
            return_type: TypeDescriptor::Void,
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // pthread.h:205
        FunctionSignature {
            name: "pthread_tls_init".into(),
            return_type: TypeDescriptor::Void,
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // sched.h:32
        FunctionSignature {
            name: "sched_get_priority_max".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("pol".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // sched.h:31
        FunctionSignature {
            name: "sched_get_priority_min".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("pol".into(), TypeDescriptor::I32)],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // sched.h:33
        FunctionSignature {
            name: "sched_getscheduler".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("pid".into(), TypeDescriptor::Struct("pid_t".into()))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // sched.h:34
        FunctionSignature {
            name: "sched_setscheduler".into(),
            return_type: TypeDescriptor::I32,
            params: vec![("pid".into(), TypeDescriptor::Struct("pid_t".into())), ("pol".into(), TypeDescriptor::I32), ("arg2".into(), TypeDescriptor::Pointer(Box::new(TypeDescriptor::Struct("sched_param param".into()))))],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
        // sched.h:28
        FunctionSignature {
            name: "sched_yield".into(),
            return_type: TypeDescriptor::I32,
            params: vec![],
            variadic: false,
            calling_convention: "ms_x64".into(),
        },
    ]
}
