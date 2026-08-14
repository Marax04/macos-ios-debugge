__int64 sub_140031320();
__int64 sub_140031285();
__int64 sub_140031096();

__int64 __fastcall sub_140030FE0(int a1, __int64 *a2, __int64 a3, __int64 a4) {
    int arg_28;
    int arg_30;
    int arg_40;
    __int64 v7;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 v10;
    __int64 v5;
    __int64 v9;
    __int64 v6;
    __int64 result;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&arg_40, xmm6);
    v7 = a3;
    v3 = (__int64)a2;
    arg_28 = a1;
    v4 = *a2;
    v2 = a2[2];
    v10 = 0x2000;
    if ((v7 & 1) != 0) {
        if (a4 <= -1025) {
            v5 = a4 + 0x400;
            a1 = result;
            a1 &= 0x1FFF;
            v9 = a4;
            v9 -= a1;
            v9 += 0x2400;
            if (v9 >= v5) v10 = v9;
            if (a1 == 0) v10 = v5;
            if (a4 == 0) {
                v7 ^= 1;
                v6 = v4;
                v6 -= v2;
                if (v6 >= 32) JUMPOUT(0x140031092);
                sub_140031320(arg_28, v3, v4);
                if ((result & 1) == 0) JUMPOUT(0x140031246);
                result = 1;
                return sub_140031285();
            }
        }
        arg_30 = 0;
        return sub_140031096();
    }
    return result;
}