// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[48];
    __int64 field_30; // offset 48
    char _pad_30[8];
    __int64 field_40; // offset 64
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[56];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
};

__int64 sub_1400F8440();
__int64 sub_1400F27F6();

__int64 __fastcall sub_140069ED0(struct Struct_1_t *a1, __int64 a2) {
    __int64 *src;
    struct Struct_2_t *ptr;
    __int64 i;
    __int64 v8;
    __int64 *dst;
    __int64 v7;
    __int64 v5;
    __int64 v4;
    __int64 v6;
    __m128i xmm0;

    src = (__int64 *)a2;
    ptr = (struct Struct_2_t *)a1;
    i = a1->field_40;
    if (i == a1->field_30) {
        v8 = ptr + 48;
        sub_1400F8440(v8);
        dst = ptr->field_38;
        if (i != 0) {
            v7 = dst + 24;
            v5 =  + i*8;
            v4 = v5 + v5*2;
            sub_1400F27F6(v7, dst, v4);
        } else {
        }
        v6 = *(src + 16);
        *(dst + 16) = v6;
        xmm0 = _mm_loadu_si128((__m128i *)src);
        _mm_storeu_si128((__m128i *)dst, xmm0);
        ++i;
        ptr->field_40 = i;
        return i;
    } else {
        dst = ptr->field_38;
        if (i != 0) {
            return (__int64)dst;
        }
        return (__int64)dst;
    }
    return (__int64)dst;
}