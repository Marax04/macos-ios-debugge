// inferred from 3 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002E830();
__int64 sub_1400360D0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14003F430(__int64 *a1) {
    int arg_8;
    __int64 v_10;
    int v_20;
    __int64 v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    __int64 v_50;
    __int64 v_58;
    __int64 src;
    char *dst;
    __int64 *dst2;
    struct Struct_1_t *result;
    __int64 *src2;
    __int64 v3;

    arg_8 = -2;
    dst2 = a1;
    a1 = dst - 64;
    sub_14002E830(a1);
    result = (struct Struct_1_t *)v_40;
    src2 = (__int64 *)v_38;
    a1 = (__int64 *)result;
    a1 = (__int64 *)(-(__int64)a1);
    if ((0 /* overflow check on (-a1) */)) {
        a1 = (__int64 *)v_30;
        v_58 = (__int64)result;
        v_50 = (__int64)src2;
        v_48 = (int)a1;
        a1 = dst - 40;
        v3 = dst - 88;
        sub_1400360D0(a1, v3);
        src2 = (__int64 *)v_20;
        result = (struct Struct_1_t *)v_28;
        result = (struct Struct_1_t *)(-(__int64)result);
        if ((0 /* overflow check on (-result) */)) JUMPOUT(0x14003f538);
    } else {
        result = 0x8000000000000000;
        v_28 = (__int64)result;
    }
    result = (struct Struct_1_t *)src2;
    result = (struct Struct_1_t *)((__int64)(__int64)result & 3);
    if (result == 1) {
        result = src2 - 1;
        v_10 = (__int64)result;
        result = *(src2 - 1);
        src = (__int64)result;
        result = *(src2 + 7);
        *dst = result;
        result = result->field_0;
        if (result != 0) {
            a1 = (__int64 *)src;
            ((__int64 (*)())result)(a1);
        }
        src2 = (__int64 *)src;
        result = *dst;
        if (result->field_8 != 0) {
            if (result->field_10 >= 17) {
                src2 = *(src2 - 8);
            }
            off_140108030();
            off_140108038(result, 0, src2);
        }
        off_140108030();
        off_140108038(result, 0, v_10);
    }
    result = 0x8000000000000000;
    *dst2 = result;
    return (__int64)result;
}