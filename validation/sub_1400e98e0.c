// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[32];
    __int64 field_38; // offset 56
    char _pad_38[156];
    __int64 field_DC; // offset 220
};

// inferred from 8 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[4];
    __int16 field_4; // offset 4
    __int16 field_6; // offset 6
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    int field_20; // offset 32
    int field_24; // offset 36
    __int64 field_28; // offset 40
};

__int64 sub_1400BDA60();
__int64 sub_1400972B0();
__int64 sub_1400F3600();
__int64 sub_1400F3B80();
__int64 sub_140011970();
__int64 off_140108030();
extern __int64 off_140108038;
extern __int64 off_140119260;
extern __int64 off_14011D3D8;
extern __int64 off_14011D398;
extern __int64 off_14011D3F8;
extern __int64 off_140119AA8;
extern __int64 off_140117680;

__int64 __fastcall sub_1400E98E0(size_t *a1, int *a2, int a3, int a4) {
    __int64 rsp;
    __int64 v_20;
    int v_28;
    __int64 v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    __int64 v9;
    __int64 *src;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 v3;
    __int64 v7;
    __int64 *result;
    __int64 v8;
    int v11;
    __int64 *src2;
    __int64 v6;

    v9 = a4;
    src = (__int64 *)a3;
    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    a1 = rsp + 64;
    sub_1400BDA60(a1, a3);
    v3 = v_48;
    v7 = v_50;
    result = (__int64 *)v_58;
    v_38 = (__int64)result;
    v8 = v_60;
    v11 = *(src + 88);
    v_20 = v7;
    v_28 = 0x60000020;
    sub_1400972B0(ptr, v9, 8, v3);
    a4 = (int)result;
    a4 >>= 32;
    if (((__int64)result & 1) != 0) {
        result = (__int64 *)((__int64)(__int64)result >> 16);
        ptr2->field_4 = 0;
        ptr2->field_6 = result;
        ptr2->field_8 = a4;
        *(__int64 *)ptr2 = (__int64)(1);
        if (v_40 != 0) {
            off_140108030(a1, a2, a3, a4);
            a1 = (size_t *)result;
            a2 = 0;
            a3 = v3;
            JUMPOUT(off_140108038);
        }
        return a3;
    }
    result = (__int64 *)v8;
    result = (__int64 *)((__int64)(__int64)result >> 32);
    while (!((result != 0))) {
        result = (__int64 *)v8;
        result += a4;
        if ((result < 0)) {
            ptr2->field_4 = 0;
            *(__int64 *)ptr2 = (__int64)(1);
            if (v_40 != 0) {
                return (__int64)result;
            }
            return (__int64)result;
        }
        a3 = ptr->field_10;
        a2 = ptr->field_38;
        a1 = a2 + 16;
        a2 += 20;
        if (a2 < a1) {
            a4 = &off_140119260;
            sub_1400F3600(a1, a2, a3, a4);
            return a4;
        }
        if (a2 > a3) {
            return a4;
        }
        a2 = ptr->field_8;
        *(__int64 *)((__int64)a2 + (__int64)a1) = result;
        ptr->field_DC = result;
        ptr2->field_8 = v8;
        ptr2->field_10 = v7;
        a1 = (size_t *)v_38;
        ptr2->field_18 = a1;
        ptr2->field_20 = a4;
        ptr2->field_24 = v11;
        ptr2->field_28 = result;
        *(__int64 *)ptr2 = (__int64)(0);
        if (v_40 != 0) {
            return (__int64)a1;
        }
        return (__int64)result;
    }
    result = &off_14011D3D8;
    v_20 = (__int64)result;
    a1 = &off_14011D398;
    a4 = &off_14011D3F8;
    src2 = rsp + 55;
    sub_1400F3B80(a1, 24, src2, a4);
    result = *a1;
    a1 = *result;
    a3 = 9;
    result = &off_140119AA8;
    src2 = (__int64 *)a1;
    do {
        a4 = (int)src2;
        src2 = (__int64 *)((__int64)(__int64)src2 >> 4);
        a3 = (int)a1;
        a3 &= 15;
        a3 = *(__int64 *)((__int64)src2 + (__int64)result);
        *(__int64 *)(rsp + a4 + 46) = a3;
        src2 = a4 - 1;
        a1 = (size_t *)src2;
    } while ((a1 > 15));
    a4 -= 2;
    result = rsp + a4;
    result += 48;
    a1 = 9;
    a1 = (size_t *)((__int64)a1 - (__int64)src2);
    v_28 = (int)a1;
    v_20 = (__int64)result;
    v6 = &off_140117680;
    return sub_140011970(a2, 1, v6, 2);
}