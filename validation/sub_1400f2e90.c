// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[56];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
extern __int64 off_14010A5A0;
extern __int64 off_140109239;
extern __int64 off_14010A568;

__int64 __fastcall sub_1400F2E90(int a1, int a2) {
    __int64 v4;
    __int64 *src;
    __int64 v8;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v7;
    __int64 v2;
    __int64 v5;
    struct Struct_1_t *ptr;

    v4 = a2;
    src = (__int64 *)a1;
    sub_14002EDF0(0, 80);
    if (ptr == 0) {
        sub_1400F3340(8, 80);
        v8 = a1;
        sub_14002EDF0(0, 72);
        if (ptr == 0) JUMPOUT(0x1400f2f53);
        v6 = &off_14010A5A0;
        *(__int64 *)ptr = (__int64)(v6);
        xmm0 = _mm_loadu_si128((__m128i *)v8);
        xmm1 = _mm_loadu_si128((__m128i *)(v8 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v8 + 32));
        _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 24), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 40), xmm2);
        v7 = &off_140109239;
        ptr->field_38 = v7;
        ptr->field_40 = 31;
        return v7;
    } else {
        v2 = &off_14010A568;
        *(__int64 *)ptr = (__int64)(v2);
        xmm0 = _mm_loadu_si128((__m128i *)v4);
        xmm1 = _mm_loadu_si128((__m128i *)(v4 + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(v4 + 32));
        _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 24), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 40), xmm2);
        xmm0 = _mm_loadu_si128((__m128i *)src);
        _mm_storeu_si128((__m128i *)(ptr + 56), xmm0);
        v5 = *(src + 16);
        ptr->field_48 = v5;
        return v5;
    }
}