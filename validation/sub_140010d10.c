extern __int64 off_14011B24D;

__int64 __fastcall sub_140010D10(__int64 a1, __int64 *a2, __int64 a3, size_t *a4) {
    __int64 *result;
    int v3;
    int v4;
    int v2;

    if (a2 != 0) {
        a2 += a1;
        a3 = &off_14011B24D;
        do {
            result = a2;
            a4 = *(a2 - 1);
            v3 = *(result - 2);
            if (v3 >= 192) {
                a2 = result - 2;
                v3 &= 31;
                v3 <<= 6;
                a4 = (size_t *)((__int64)(__int64)a4 & 63);
                a4 = (size_t *)((__int64)(__int64)a4 | v3);
                v3 = a4 - 9;
                if (v3 < 5) {
                    result = 0;
                    return (__int64)result;
                }
                if (a4 == 32) {
                    return (__int64)result;
                }
                if (a4 < 128) JUMPOUT(0x140010e44);
                v3 = (int)a4;
                v3 >>= 8;
                if (v3 > 31) {
                    if (v3 == 32) {
                        a4 = *(a4 + a3);
                        a4 = (size_t *)((__int64)(__int64)a4 >> 1);
                        if (((__int64)a4 & 1) == 0) JUMPOUT(0x140010e44);
                        return (__int64)a4;
                    }
                    if (v3 != 48) JUMPOUT(0x140010e44);
                    a4 = (a4 == 0x3000) ? 1 : 0;
                    return (__int64)a4;
                }
                if (v3 == 0) {
                    a4 = *(a4 + a3);
                    return (__int64)a4;
                }
                if (v3 != 22) JUMPOUT(0x140010e44);
                a4 = (a4 == 0x1680) ? 1 : 0;
                return (__int64)a4;
            }
            v4 = *(result - 3);
            if (v4 >= 192) {
                a2 = result - 3;
                v4 &= 15;
                v4 <<= 6;
                v3 &= 63;
                v3 |= v4;
                return v3;
            }
            a2 = result - 4;
            v2 = *(result - 4);
            v2 &= 7;
            v2 <<= 6;
            v4 &= 63;
            v4 |= v2;
            return v4;
        } while (a1 != a2);
    }
    return (__int64)result;
}