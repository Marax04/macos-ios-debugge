// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[56];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
extern __int64 off_14010A6F0;
extern __int64 off_14010A610;

__int64 __fastcall sub_1400F2F70(int a1, int a2, __int64 a3) {
    __int64 v4;
    __int64 *src;
    __int64 v2;
    __int64 v9;
    __int64 v8;
    __int64 v7;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v5;
    __int64 v6;
    struct Struct_1_t *ptr;

    v4 = a2;
    src = (__int64 *)a1;
    sub_14002EDF0(0, 80);
    if (ptr == 0) {
        sub_1400F3340(8, 80);
        v2 = a3;
        v9 = a2;
        v8 = a1;
        sub_14002EDF0(0, 72);
        if (ptr == 0) JUMPOUT(0x1400f3032);
        v7 = &off_14010A6F0;
        *(__int64 *)ptr = (__int64)(v7);
        xmm0 = _mm_loadu_si128((__m128i *)v2);
        xmm1 = _mm_loadu_si128((__m128i *)(v2 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v2 + 32));
        _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 24), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 40), xmm2);
        ptr->field_38 = v8;
        ptr->field_40 = v9;
        return _mm_cvtsi128_si64(xmm2);
    } else {
        v5 = &off_14010A610;
        *(__int64 *)ptr = (__int64)(v5);
        xmm0 = _mm_loadu_si128((__m128i *)v4);
        xmm1 = _mm_loadu_si128((__m128i *)(v4 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v4 + 32));
        _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 24), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 40), xmm2);
        xmm0 = _mm_loadu_si128((__m128i *)src);
        _mm_storeu_si128((__m128i *)(ptr + 56), xmm0);
        v6 = *(src + 16);
        ptr->field_48 = v6;
        return v6;
    }
}