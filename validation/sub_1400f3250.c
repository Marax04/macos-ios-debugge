// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[56];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F2DE0();
extern __int64 off_14010A530;

__int64 __fastcall sub_1400F3250(int *a1, int a2, __int64 a3) {
    __int64 v2;
    __int64 v3;
    __int64 v4;
    __int64 *src;
    __int64 v5;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    struct Struct_1_t *ptr;

    v2 = a3;
    v3 = a2;
    v4 = (__int64)a1;
    sub_14002EDF0(0, 72);
    if (ptr == 0) {
        sub_1400F3340(8, 72);
        src = (__int64 *)a1;
        a1 = *(a1 + 8);
        v5 = *(src + 24);
        if (a1 == 1) JUMPOUT(0x1400f32f1);
        if (a1 != 0) JUMPOUT(0x1400f330a);
        if (v5 != 0) JUMPOUT(0x1400f330a);
        a1 = 1;
        a2 = 0;
        return sub_1400F2DE0();
    } else {
        v6 = &off_14010A530;
        *(__int64 *)ptr = (__int64)(v6);
        xmm0 = _mm_loadu_si128((__m128i *)v2);
        xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v2 + 32));
        _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 24), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 40), xmm2);
        ptr->field_38 = v4;
        ptr->field_40 = v3;
        return _mm_cvtsi128_si64(xmm2);
    }
}