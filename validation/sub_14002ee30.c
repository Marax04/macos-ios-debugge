// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[16];
    char field_10; // offset 16
    __int64 field_11; // offset 17
};

// inferred from 2 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[16];
    char field_10; // offset 16
    __int64 field_11; // offset 17
};

__int64 sub_14002EE50();
__int64 sub_14002EE60();
__int64 sub_1400277DC();
extern __int64 off_140114008;
extern __int64 off_140114040;

__int64 __fastcall sub_14002EE30(__int64 a1,struct Struct_1_t *a2, int a3, __int64 a4) {
    __int64 rsp;
    int arg_10;
    int arg_8;
    int v_10;
    int v_18;
    __int64 v_20;
    __int64 v_8;
    __int64 *dst;
    __m128i xmm0;
    __int64 *src;
    struct Struct_2_t *ptr;
    __int64 v2;
    struct Struct_3_t *ptr2;
    __int64 result;
    __int64 v6;
    __int64 v3;
    struct Struct_4_t *ptr3;
    __int64 v9;

    dst = rsp + 64;
    xmm0 = _mm_loadu_si128((__m128i *)a1);
    _mm_storeu_si128((__m128i *)&v_18, xmm0);
    v_8 = a1;
    src = dst - 24;
    sub_14002EE50(src);
    sub_14002EE60();
    dst = rsp + 80;
    *dst = -2;
    ptr = *src;
    a3 = ptr->field_8;
    a2 = ptr->field_18;
    if (a3 == 1) {
        if (a2 == 0) {
            a2 = ptr->field_0;
            ptr = a2->field_0;
            a2 = a2->field_8;
            v_20 = (__int64)ptr;
            v_18 = (int)a2;
            v2 = arg_8;
            ptr2 = (struct Struct_3_t *)arg_10;
            a4 = ptr2->field_10;
            result = ptr2->field_11;
            v_20 = result;
            a2 = &off_140114008;
            src = dst - 32;
            sub_1400277DC(src, a2, v2, a4);
        }
    } else {
        if (a3 == 0) {
            if (a2 == 0) {
                result = 1;
                a2 = 0;
                return (__int64)a2;
            }
        }
    }
    v_8 = (__int64)src;
    v6 = 0x8000000000000000;
    v_20 = v6;
    v3 = arg_8;
    ptr3 = (struct Struct_4_t *)arg_10;
    a4 = ptr3->field_10;
    result = ptr3->field_11;
    v_20 = result;
    a2 = &off_140114040;
    v9 = dst - 32;
    sub_1400277DC(v9, a2, v3, a4);
    v_10 = (int)a2;
    dst = a2 + 80;
    result = v_20;
    result <<= 1;
    if (result != 0) JUMPOUT(0x14002ef32);
    return result;
}