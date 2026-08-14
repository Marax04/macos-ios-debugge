// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[8];
    __int64 field_170; // offset 368
};

__int64 sub_1400F27F0();
__int64 sub_14004CC49();

__int64 __fastcall sub_14004CB70(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int arg_8;
    int v_200;
    int v_38;
    __int64 *src;
    __int64 v1;
    __int64 v5;
    __int64 v6;
    __int64 v4;
    __int64 v2;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_200, xmm6);
    src = a2->field_160;
    if (src != a2->field_170) {
        v1 = src + 328;
        a2->field_160 = v1;
        v5 = *src;
        if (v5 != 12) {
            v6 = (__int64)a1;
            a2 = src + 176;
            src += 8;
            a1 = rsp + 32;
            sub_1400F27F0(a1, a2, 144);
            a1 = rsp + 344;
            sub_1400F27F0(a1, src, 168);
            v4 = v_38;
            a1 = 0x8000000000000003;
            if (v4 != a1) {
                a1 = 0x8000000000000002;
                if (v4 >= a1) JUMPOUT(0x14004cc3f);
            }
            v1 = 0;
            return sub_14004CC49();
        }
    }
    v2 = 0x8000000000000000;
    arg_8 = v2;
    *a1 = 2;
    xmm6 = _mm_load_si128((__m128i *)&v_200);
    return _mm_cvtsi128_si64(xmm6);
}