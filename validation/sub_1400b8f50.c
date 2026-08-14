// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 __fastcall sub_1400B8F50(__int64 *a1,struct Struct_1_t *a2) {
    __int64 *result;
    __int64 v6;
    __int64 i;
    __m128i xmm0;
    int v7;
    int v8;
    int v3;
    int v4;
    int v2;
    int v12;
    int v11;
    __int64 v10;
    __m128i xmm1;
    int v9;

    result = a2->field_0;
    v6 = a2->field_8;
    if (result != v6) {
        i = ((__int64 *)a2)[2];
        xmm0 = _mm_setzero_si128();
        v7 = 0x7865742E;
        v8 = 0x7461642E;
        v3 = 0x7273722E;
        v4 = 0x6164722E;
        v2 = 0x6164702E;
        v12 = 0x6C65722E;
        v11 = 0x6164692E;
        v10 = 0x6D6172665F68652E;
        do {
            xmm1 = _mm_cvtsi32_si128(*result);
            xmm1 = _mm_unpacklo_epi8(xmm1, xmm1);
            xmm1 = _mm_unpacklo_epi16(xmm1, xmm1);
            xmm1 = _mm_cmpeq_epi8(xmm1, xmm0);
            v9 = _mm_movemask_ps(xmm1);
            result += 28;
            ++i;
            ((__int64 *)a2)[2] = (__int64)(i);
        } while (result != v6);
        *(__int64 *)a2 = (__int64)(result);
    }
    result = 0;
    *a1 = result;
    return (__int64)result;
}