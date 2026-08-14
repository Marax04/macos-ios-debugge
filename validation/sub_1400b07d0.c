__int64 __fastcall sub_1400B07D0(__int64 *a1, size_t a2, __int64 a3) {
    __int64 *result;
    __int64 v3;
    __int64 v4;
    __int64 v5;
    __int64 v2;

    result = 0;
    if (v2 != 1) {
        do {
            v3 = v2;
            v3 >>= 1;
            v4 = v3 + result;
            v5 = v4 + v4*4;
            v5 = *(a1 + v5*8 + 32);
            if (a3 >= v5) result = v4;
            v2 -= v3;
        } while (v2 > 1);
    }
    a2 = result + (__int64)(__int64)result*4;
    v3 = *(a1 + a2*8 + 32);
    a2 = 0;
    a2 = (a3 >= v3) ? 1 : 0;
    a2 += (__int64)result;
    if (!((a2 == 0))) {
        --a2;
        result = a2 + a2*4;
        v3 = *(a1 + (__int64)(__int64)result*8 + 32);
        if (a3 >= v3) {
            result = a1 + (__int64)(__int64)result*8;
            v3 += *(result + 24);
            result = 0;
            result = (a3 < v3) ? 1 : 0;
            return (__int64)result;
        }
    }
    result = 0;
    return (__int64)result;
}