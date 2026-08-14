__int64 sub_1400F27F6();

__int64 __fastcall sub_1400F9EC9(int a1, int a2, __int64 a3, __int64 a4) {
    int v_20;
    int v_28;
    __int64 *result;
    __int64 v4;
    __int64 *dst;
    __int64 v3;
    __int64 v7;
    __int64 v5;
    __int64 v6;

    if (0 /* unresolved: flags !OF */) v3 = *(result + 16);
    a1 = v5;
    if (v5 < 16) {
        a1 = 16;
        a3 = v5;
    }
    a1 += v3;
    sub_1400F27F6(a1, v3);
    result = v3 - 16;
    v4 = 1;
    a1 = 0;
    a3 = 0;
    do {
        /* cmp a3 , v5 */;
        v4 = a3;
        v4 += 0;
    } while (a3 < v5);
    if (v6 < 8) v7 = v6;
    dst = (__int64 *)v_28;
    v3 = v_20;
    v7 -= v3;
    *(dst + 16) = v7;
    result = 0x8000000000000001;
    return (__int64)result;
}