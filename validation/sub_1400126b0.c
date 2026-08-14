extern __int64 off_14010F31C;
extern __int64 off_14010AFB8;

__int64 __fastcall sub_1400126B0(int a1, __int64 a2, int a3) {
    __int64 *result;
    __int64 v5;
    __int64 *src;
    __int64 v6;
    __int64 v2;
    __int64 v4;
    __int64 v3;
    __int64 v8;

    a3 = 0;
    a3 = (a1 >= 0x10EAB) ? 1 : 0;
    result = (__int64 *)a1;
    result = (__int64 *)((__int64)(__int64)result << 11);
    a3 <<= 4;
    v5 = a3 + 8;
    src = &off_14010F31C;
    v6 = *(src + a3*4 + 32);
    v6 <<= 11;
    if (v6 > result) v5 = a3;
    v2 = v5 + 4;
    v6 = *(src + v5*4 + 16);
    v6 <<= 11;
    if (v6 > result) v2 = v5;
    v4 = v2 + 2;
    v6 = *(src + v2*4 + 8);
    v6 <<= 11;
    if (v6 > result) v4 = v2;
    v3 = v4 + 1;
    v6 = *(src + v4*4 + 4);
    v6 <<= 11;
    if (v6 > result) v3 = v4;
    v6 = v3 + 1;
    v5 = *(src + v3*4 + 4);
    v5 <<= 11;
    if (v5 > result) v6 = v3;
    a3 = *(src + v6*4);
    a3 <<= 11;
    v5 = 0;
    v5 = (a3 == result) ? 1 : 0;
    v4 += v6;
    result = *(src + v4*4);
    result = (__int64 *)((__int64)(__int64)result >> 21);
    a3 = 767;
    if (v4 <= 31) {
        a3 = *(src + v4*4 + 4);
        a3 >>= 21;
        if (v4 == 0) {
            v6 = 0;
            v8 = (__int64)result;
            v8 = ~v8;
            v8 += v3;
            if ((v8 != 0)) {
                a1 -= v6;
                --v3;
                v5 = 0;
                v8 = &off_14010AFB8;
                v6 = v5;
                v5 = *(result + v8);
                v5 += v6;
                while (v5 <= a1) {
                    ++result;
                }
            } else {
            }
            result = (__int64 *)((__int64)(__int64)result & 1);
            return (__int64)result;
        } else {
            v6 = 0x1FFFFF;
            v6 &= *(src + v4*4 - 4);
            v8 = (__int64)result;
            v8 = ~v8;
            v8 += v3;
            if (!((v8 == 0))) {
                return v8;
            }
            return v8;
        }
        return v8;
    }
    return (__int64)result;
}