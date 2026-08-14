// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F74E0();

__int64 __fastcall sub_140044D9C() {
    int v_18;
    int v_28;
    int v_38;
    int v_48;
    int v_58;
    __int64 i;
    __int64 *result;
    __int64 v2;
    __int64 v3;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    struct Struct_1_t *ptr;

    i = ptr->field_10;
    if (i == ptr->field_0) {
        sub_1400F74E0(ptr);
    }
    result = ptr->field_8;
    v2 = i + i*8;
    v3 = v_18;
    *(result + v2*8 + 64) = v3;
    xmm0 = _mm_loadu_si128((__m128i *)&v_58);
    xmm1 = _mm_loadu_si128((__m128i *)&v_48);
    xmm2 = _mm_loadu_si128((__m128i *)&v_38);
    xmm3 = _mm_loadu_si128((__m128i *)&v_28);
    _mm_storeu_si128((__m128i *)(result + v2*8 + 48), xmm3);
    _mm_storeu_si128((__m128i *)(result + v2*8 + 32), xmm2);
    _mm_storeu_si128((__m128i *)(result + v2*8 + 16), xmm1);
    _mm_storeu_si128((__m128i *)(result + v2*8), xmm0);
    ++i;
    ptr->field_10 = i;
    return (__int64)result;
}