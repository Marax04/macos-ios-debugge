__int64 __fastcall sub_14008B890(__int64 *a1, __int64 a2) {
    __int64 *result;
    __int64 v4;
    __int64 *src;
    __int64 i;
    int v7;
    int v3;
    __int64 v2;

    result = *a1;
    v4 = a1[1];
    src = a1 + 24;
    i = 2;
    v7 = v4;
    if (v4 >= result) {
        v3 = v7;
        v7 = *src;
        while (v7 >= v3) {
            ++i;
            src += 12;
            if (v4 < result) {
                result = a2 + a2*2;
                a2 >>= 1;
                result = a1 + (__int64)(__int64)result*4;
                result -= 4;
                a1 += 8;
                do {
                    v4 = *(a1 - 8);
                    v2 = *(result - 8);
                    *(a1 - 8) = v2;
                    *(result - 8) = v4;
                    v4 = *a1;
                    i = *result;
                    *a1 = i;
                    *result = v4;
                    a1 += 12;
                    result -= 12;
                    --a2;
                } while ((a2 != 0));
            }
            return a2;
        }
    } else {
        v3 = v7;
        v7 = *src;
        while (v7 < v3) {
            ++i;
            src += 12;
            return (__int64)src;
        }
    }
    if (i != a2) JUMPOUT(0x14008b93b);
    return (__int64)result;
}