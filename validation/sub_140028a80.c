__int64 sub_140028050();
__int64 sub_1400281E0();
__int64 sub_1400F1D90();
__int64 sub_140028C81();
__int64 off_140108388();
__int64 off_140108068();
__int64 off_1401080C0();
__int64 off_1401080C8();
__int64 off_140108380();
extern __int64 off_140112D18;
extern __int64 off_1401130D0;

__int64 __fastcall sub_140028A80(int *a1, int a2, int a3, int a4) {
    int arg_10;
    int arg_14;
    int arg_1fb8;
    int arg_8;
    __int64 v_20;
    int v_28;
    int v_30;
    int v_38;
    int src;
    char *src2;
    __m128i xmm0;
    __int64 result;
    __int64 v3;
    __int64 v5;
    __int64 v4;
    __int64 v6;
    __int64 v7;
    __int64 v2;
    __int64 v8;

    xmm0 = _mm_loadu_si128((__m128i *)&off_140112D18);
    _mm_store_si128((__m128i *)&*src2, xmm0);
    result = 0xFFFFFFFF;
    if (a3 < result) result = a3;
    v3 = *a1;
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_38, xmm0);
    v_30 = result;
    v_28 = a2;
    v_20 = (__int64)src2;
    off_140108388(v3, 0, 0, 0);
    if (result == 259) {
        off_140108068(v3, 0xFFFFFFFF);
        result = *src2;
        if (result == 259) {
            arg_10 = 0;
            arg_14 = 0;
            v5 = &off_1401130D0;
            v_38 = v5;
            v_30 = 1;
            v_28 = 8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)&v_20, xmm0);
            a1 = src2 + 16;
            a2 = src2 - 56;
            sub_140028050(a1, a2);
            src = v5;
            a1 = src2 - 8;
            sub_1400281E0(a1);
            /* int $41 */;
            result = 0x2068;
            sub_1400F1D90(7);
            v3 = a3;
            v4 = (__int64)a1;
            if (v3 >= 0x1001) JUMPOUT(0x140028c2a);
            v6 = src2 - 72;
            v_20 = v6;
            v_28 = 0x1000;
            off_1401080C0(0xFDE9, 8, a2, v3);
            if (result == 0) JUMPOUT(0x140028d9c);
            v7 = result;
            if (result >= 0x1001) JUMPOUT(0x140028d85);
            arg_1fb8 = 0;
            v_20 = 0;
            v2 = src2 - 72;
            a4 = src2 + 0x1FB8;
            off_1401080C8(v4, v2, result, a4);
            if (result == 0) JUMPOUT(0x140028c6c);
            v8 = arg_1fb8;
            if (v8 != v7) JUMPOUT(0x140028c94);
            result = 0;
            return sub_140028C81();
        }
    }
    if (result < 0) {
        off_140108380(result, a2);
        a2 = result;
        a2 <<= 32;
        a2 |= 2;
        result = 1;
        return result;
    } else {
        a2 = arg_8;
        result = 0;
        return result;
    }
}