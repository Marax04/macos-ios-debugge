// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[48];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
};

__int64 sub_14000EFE0();
extern __int64 off_1400269E0;
extern __int64 off_14004F430;
extern __int64 off_140114F88;

__int64 __fastcall sub_1400F7BC0(__int64 *a1, __int64 str, __int64 a3, __int64 a4) {
    int v_28;
    int v_38;
    __int64 v_40;
    int v_48;
    int v_58;
    __int64 v_60;
    int v_68;
    int v_70;
    char *str2;
    char *str3;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v4;
    __int64 v5;
    __int64 result;
    __int64 v6;

    ptr = (struct Struct_1_t *)a1;
    str2 = (char *)a3;
    v_28 = a4;
    str3 = (char *)v6;
    v2 = &off_1400269E0;
    v_38 = v2;
    v_40 = (__int64)str2;
    v4 = &off_14004F430;
    v_48 = v4;
    v5 = &off_140114F88;
    str = v5;
    v_58 = 2;
    v_60 = (__int64)str3;
    v_68 = 2;
    v_70 = 0;
    a1 += 24;
    sub_14000EFE0(a1, str);
    *(__int64 *)ptr = (__int64)(0);
    ptr->field_30 = 0;
    ptr->field_38 = 8;
    ptr->field_40 = 0;
    result = 0x8000000000000000;
    ptr->field_48 = result;
    return result;
}