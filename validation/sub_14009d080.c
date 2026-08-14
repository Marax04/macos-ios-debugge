__int64 __fastcall sub_14009D080(__int64 *a1, int *a2, __int64 *a3, size_t a4) {
    __int64 *src;
    __int64 *src2;
    __int64 v2;
    __int64 v8;
    __int64 v7;
    __int64 v9;
    __int64 v5;
    __int64 v10;
    __int64 v6;
    __int64 result;

    src = a3;
    src2 = (__int64 *)a2;
    if (a4 >= 8) {
        a4 >>= 3;
        v2 = a4;
        v2 <<= 4;
        v8 = a1 + v2;
        v7 = a4 + a4*8;
        v9 = v7 + v7*2;
        v9 += a4;
        v5 = a1 + v9;
        v10 = a4;
        sub_14009D080(a1, v8, v5, a4);
        a2 = src2 + v2;
        v6 = src2 + v9;
        sub_14009D080(src2, a2, v6, v10);
        src2 = (__int64 *)v7;
        v2 += (__int64)src;
        v9 += (__int64)src;
        sub_14009D080(src, v2, v9, v10);
        a1 = (__int64 *)v7;
        src = (__int64 *)v7;
    }
    result = *a1;
    a2 = *src2;
    a3 = (result < a2) ? 1 : 0;
    a4 = *src;
    result = (result < a4) ? 1 : 0;
    result ^= (__int64)a3;
    a2 = (a2 < a4) ? 1 : 0;
    a2 = (int *)((__int64)(__int64)a2 ^ (__int64)a3);
    if (a2 != 0) src2 = src;
    if (result != 0) src2 = a1;
    result = (__int64)src2;
    return result;
}