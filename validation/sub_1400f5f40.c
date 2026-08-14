// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F2C50();

__int64 __fastcall sub_1400F5F40(int *a1, int a2, __int64 *a3) {
    int v_20;
    int v_28;
    int v_38;
    char *str;
    __int64 *dst;
    __int64 v4;
    __int64 *src;
    __int64 v7;
    __int64 v9;
    __int64 v5;
    __int64 result;
    __int64 v8;
    __m128i xmm0;
    struct Struct_1_t *ptr;

    dst = a3;
    v4 = a2;
    src = (__int64 *)a1;
    sub_14002EDF0(0, 40);
    if (ptr == 0) {
        sub_1400F3340(8, 40);
        a2 += (__int64)a3;
        if ((a2 < 0)) JUMPOUT(0x1400f5ff9);
        dst = (__int64 *)a1;
        v7 = *a1;
        v9 = v7 + v7;
        if (a2 > v9) v9 = a2;
        v4 = 8;
        if (v9 >= 9) v4 = v9;
        v5 = *(dst + 8);
        v_28 = 1;
        v_20 = 1;
        sub_1400F2C50(str, v7, v5);
        if (str == 1) JUMPOUT(0x1400f6000);
        result = v_38;
        *(dst + 8) = result;
        *dst = v4;
        return result;
    } else {
        v8 = *(src + 16);
        ptr->field_10 = v8;
        xmm0 = _mm_loadu_si128((__m128i *)src);
        _mm_storeu_si128((__m128i *)ptr, xmm0);
        ptr->field_18 = v4;
        ptr->field_20 = dst;
        return result;
    }
}