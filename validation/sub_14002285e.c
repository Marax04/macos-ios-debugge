// inferred from 2 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 4 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400F2808();
__int64 sub_140022A41();

__int64 __fastcall sub_14002285E(__int64 *a1, size_t *a2, int a3, int a4) {
    int arg_1;
    __int64 arg_1a8;
    int arg_1b0;
    int arg_1b8;
    __int64 arg_1c0;
    __int64 arg_1c8;
    __int64 arg_1d0;
    __int64 arg_1d8;
    int arg_2;
    int arg_3;
    char *dst;
    struct Struct_2_t *ptr;
    struct Struct_3_t *ptr2;
    struct Struct_1_t *result;
    int v10;
    __int64 i;
    int v5;
    __int64 v3;
    __int64 *i2;
    __int64 v8;
    __int64 v9;

    ptr = (struct Struct_2_t *)a2;
    ptr2 = (struct Struct_3_t *)a1;
    a1 = dst - 88;
    sub_1400F2808(a1, 0, 512);
    a1 = ptr2->field_18;
    arg_1b8 = (int)a1;
    if (a1 == 0) {
        a2 = ptr2->field_0;
        a3 = ptr2->field_8;
        a1 = ptr->field_0;
        result = ptr->field_8;
        result = result->field_18;
        JUMPOUT(result);
    } else {
        result = ptr2->field_10;
        arg_1c0 = (__int64)result;
        v10 = result->field_0;
        a1 = ptr2->field_0;
        result = ptr2->field_8;
        arg_1b0 = (int)a1;
        arg_1a8 = (__int64)result;
        if (result == 0) {
            i = 0;
        } else {
            result = (struct Struct_1_t *)((__int64)result + (__int64)a1);
            i = 0;
            do {
                v5 = *a1;
                a2 = (size_t *)v5;
                a3 = (int)a2;
                a3 &= 31;
                v3 = arg_1;
                v3 &= 63;
                if (a2 <= 223) {
                    a1 += 2;
                    a3 <<= 6;
                    a3 |= v3;
                    a2 = (size_t *)a3;
                    if (i == 128) JUMPOUT(0x140022bd5);
                    *(dst + i*4 - 88) = a2;
                    ++i;
                    if (a1 != result) {
                    }
                    result = (struct Struct_1_t *)arg_1b8;
                    i2 = (__int64 *)arg_1c0;
                    v8 = (__int64)i2 + (__int64)result;
                    result =  + i*4 + 4;
                    arg_1d8 = (__int64)result;
                    result = 700;
                    arg_1d0 = (__int64)result;
                    v9 = 72;
                    result = 128;
                    arg_1c8 = (__int64)result;
                    a1 = 0;
                    ++i2;
                    a4 = 1;
                    v5 = 1;
                    a2 = 0;
                    v3 = 36;
                    a3 = 0;
                    result = (struct Struct_1_t *)v3;
                    result -= v9;
                    ptr2 = 0;
                    if (result >= 0) ptr2 = result;
                    ptr2 += 0;
                    result = 26;
                    if (ptr2 >= 26) ptr2 = result;
                    if (((__int64)a2 & 1) == 0) JUMPOUT(0x140022a34);
                    if (i2 == v8) JUMPOUT(0x140022bd5);
                    result = *i2;
                    ++i2;
                    return sub_140022A41();
                }
                a4 = arg_2;
                v3 <<= 6;
                a4 &= 63;
                a4 |= v3;
                if (v5 < 240) {
                    a1 += 3;
                    a3 <<= 12;
                    a4 |= a3;
                    a2 = (size_t *)a4;
                    return (__int64)a2;
                }
                a2 = (size_t *)arg_3;
                a3 &= 7;
                a3 <<= 18;
                a4 <<= 6;
                a2 = (size_t *)((__int64)(__int64)a2 & 63);
                a2 = (size_t *)((__int64)(__int64)a2 | a4);
                a2 = (size_t *)((__int64)(__int64)a2 | a3);
                if (a2 != 0x110000) {
                    a1 += 4;
                    return (__int64)a1;
                }
            } while (true);
        }
        return (__int64)a1;
    }
    return (__int64)result;
}