__int64 __fastcall sub_1400BCA50(__int64 *a1, __int64 *a2, __int64 *a3, size_t a4) {
    __int64 *src;
    __int64 *src2;
    __int64 v2;
    __int64 v8;
    __int64 v5;
    __int64 v9;
    __int64 v6;
    __int64 result;
    __int64 v7;

    src = a3;
    src2 = a2;
    if (a4 >= 8) {
        a4 >>= 3;
        v2 = a4;
        v2 <<= 6;
        a2 = a1 + v2;
        v8 = a4 * 112;
        v5 = a1 + v8;
        v9 = a4;
        sub_1400BCA50(a1, a2, v5, a4);
        a2 = src2 + v2;
        v6 = src2 + v8;
        sub_1400BCA50(src2, a2, v6, v9);
        src2 = (__int64 *)result;
        v2 += (__int64)src;
        v8 += (__int64)src;
        sub_1400BCA50(src, v2, v8, v9);
        a1 = (__int64 *)result;
        src = (__int64 *)result;
    }
    result = *a1;
    a2 = *src2;
    a3 = (result < a2) ? 1 : 0;
    v7 = *src;
    result = (result < v7) ? 1 : 0;
    result ^= (__int64)a3;
    a2 = (a2 < v7) ? 1 : 0;
    a2 = (__int64 *)((__int64)(__int64)a2 ^ (__int64)a3);
    if (a2 != 0) src2 = src;
    if (result != 0) src2 = a1;
    result = (__int64)src2;
    return result;
}