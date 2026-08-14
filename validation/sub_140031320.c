// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140031510();
__int64 sub_1400F27F0();
extern __int64 off_140121A30;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140031320(int a1, size_t *a2) {
    int v_30;
    int v_40;
    char *dst;
    struct Struct_1_t *ptr;
    __int64 v4;
    __m128i xmm0;
    __int64 v2;
    __int64 *src;
    __int64 v6;
    __int64 v5;
    __int64 result;

    *dst = -2;
    ptr = (struct Struct_1_t *)a2;
    v4 = a1;
    xmm0 = _mm_setzero_si128();
    _mm_store_si128((__m128i *)&v_30, xmm0);
    _mm_store_si128((__m128i *)&v_40, xmm0);
    v2 = dst - 64;
    src = &off_140121A30;
    v6 = off_140108030;
    v5 = off_140108038;
    sub_140031510(v4, v2);
    while ((result & 1) != 0) {
        a1 = (int)a2;
        a1 &= 3;
        result = 1;
        a1 = *(src + a1*4);
        a1 += (__int64)src;
        JUMPOUT(a1);
        return a1;
    }
    if (a2 >= 33) JUMPOUT(0x14003146d);
    result = ptr->field_0;
    v4 = ptr->field_10;
    result -= v4;
    if (result < a2) JUMPOUT(0x140031481);
    v2 = (__int64)a2;
    a1 = ptr->field_8;
    a1 += v4;
    a2 = dst - 64;
    sub_1400F27F0(a1, a2, v2);
    a2 = (size_t *)v2;
    result = v2;
    result += v4;
    ptr->field_10 = result;
    result = 0;
    return result;
}