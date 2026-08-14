// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[56];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
extern __int64 off_14010A648;
extern __int64 off_14010A6F0;

__int64 __fastcall sub_1400F2FE0(int a1, int a2, __int64 a3) {
    __int64 v2;
    __int64 v3;
    __int64 v4;
    __int64 v7;
    __int64 v8;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v5;
    struct Struct_1_t *ptr;

    v2 = a3;
    v3 = a2;
    v4 = a1;
    sub_14002EDF0(0, 72);
    if (ptr == 0) {
        sub_1400F3340(8, 72);
        v7 = a2;
        v8 = a1;
        sub_14002EDF0(0, 168);
        if (ptr == 0) JUMPOUT(0x1400f30d2);
        v6 = &off_14010A648;
        *(__int64 *)ptr = (__int64)(v6);
        xmm0 = _mm_loadu_si128((__m128i *)v7);
        xmm1 = _mm_loadu_si128((__m128i *)(v7 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v7 + 32));
        _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 24), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 40), xmm2);
        xmm0 = _mm_loadu_si128((__m128i *)v8);
        xmm1 = _mm_loadu_si128((__m128i *)(v8 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v8 + 32));
        xmm3 = _mm_loadu_si128((__m128i *)(v8 + 48));
        _mm_storeu_si128((__m128i *)(ptr + 56), xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 72), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 88), xmm2);
        _mm_storeu_si128((__m128i *)(ptr + 104), xmm3);
        xmm0 = _mm_loadu_si128((__m128i *)(v8 + 64));
        _mm_storeu_si128((__m128i *)(ptr + 120), xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)(v8 + 80));
        _mm_storeu_si128((__m128i *)(ptr + 136), xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)(v8 + 96));
        _mm_storeu_si128((__m128i *)(ptr + 152), xmm0);
        return 0;
    } else {
        v5 = &off_14010A6F0;
        *(__int64 *)ptr = (__int64)(v5);
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