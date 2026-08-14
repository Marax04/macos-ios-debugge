__int64 __fastcall sub_14000F3A0(__int64 *a1, __int64 *a2, int a3, size_t a4) {
    char *dst;
    __int64 v3;
    __int64 v4;
    __int64 v6;
    __int64 v2;
    __int64 *src;
    __int64 result;

    *dst = -2;
    v3 = a3;
    v4 = (__int64)a2;
    if (a3 != 0) {
        v6 = v4 + v3;
        a2 = v4 + 1;
        v2 = 0;
        src = (__int64 *)v4;
        do {
            a4 = *src;
            a3 = 1;
            src = a2;
            v2 += a3;
            a2 = 0;
            a2 = (src != v6) ? 1 : 0;
            a2 = (__int64 *)((__int64)a2 + (__int64)src);
        } while (src != v6);
    }
    *(a1 + 8) = v4;
    a1[2] = v3;
    result = 0x8000000000000000;
    *a1 = result;
    return result;
}