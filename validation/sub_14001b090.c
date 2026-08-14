__int64 sub_14001B158();

__int64 __fastcall sub_14001B090(__int64 a1, __int64 *a2, __int64 a3, __int64 a4) {
    __int64 v5;
    __int64 v10;
    __int64 v8;
    __int64 v7;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 v9;
    __int64 result;

    v5 = a2 + 7;
    v5 &= -8;
    v5 -= (__int64)a2;
    if ((v5 != 0)) {
        for (a4 = 0; v5 != a4; ++a4) {
            if (*(a2 + a4) == a1) JUMPOUT(0x14001b153);
        }
        v10 = a3 - 16;
        if (v5 <= v10) {
            v8 = 0x101010101010101;
            v8 *= a1;
            v7 = 0x101010101010100;
            v3 = 0x8080808080808080;
            v4 = *(a2 + v5);
            v4 ^= v8;
            v2 = v7;
            v2 -= v4;
            v2 |= v4;
            v4 = *(a2 + v5 + 8);
            v4 ^= v8;
            v9 = v7;
            v9 -= v4;
            v9 |= v4;
            v9 &= v2;
            v9 = ~v9;
            while ((v9 & v3) == 0) {
                v5 += 16;
            }
        }
        a3 -= v5;
        if ((a3 != 0)) JUMPOUT(0x14001b130);
        result = 0;
        return sub_14001B158();
    } else {
        v10 = a3 - 16;
        v5 = 0;
    }
    return result;
}