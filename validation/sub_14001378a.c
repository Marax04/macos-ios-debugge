// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400138C0();
__int64 sub_14001385A();
__int64 sub_140013814();
extern __int64 off_140121048;

__int64 __fastcall sub_14001378A() {
    int arg_4;
    int v_28;
    int v_8;
    __int64 v1;
    __int64 v9;
    __int64 *src;
    __int64 v3;
    __int64 v10;
    __int64 v8;
    __int64 v7;
    int v4;
    int v11;
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 *dst;

    v1 = 0;
    v9 = v11;
    v9 -= (__int64)src;
    if (v9 < 0) v9 = v1;
    src = (__int64 *)v2;
    src = (__int64 *)((__int64)(__int64)src & 0x9FE00000);
    src = (__int64 *)((__int64)(__int64)src | 0x20000030);
    ptr->field_10 = src;
    v3 = v_8;
    if (v3 != 0) JUMPOUT(0x1400136be);
    v10 = 0;
    v10 += v1;
    v1 = v9;
    if (v10 >= v1) {
        v8 = ptr->field_0;
        v9 = ptr->field_8;
        v7 = dst - 32;
        sub_1400138C0(v8, v9, v7);
        ptr->field_10 = v2;
        return sub_14001385A();
    } else {
        v4 = v9;
        v4 -= v10;
        v1 = (__int64)src;
        v1 >>= 29;
        v1 &= 3;
        src = &off_140121048;
        v1 = *(src + v1*4);
        v1 += (__int64)src;
        v_28 = v2;
        *dst = v9;
        arg_4 = v4;
        JUMPOUT(v1);
        return sub_140013814();
    }
}