__int64 sub_140017D4E();
__int64 sub_140017D3E();
__int64 sub_140017D38();
__int64 sub_140017D3C();
extern __int64 off_1401133CD;

__int64 __fastcall sub_140017B60(__int64 *a1, __int64 *a2, __int64 a3, __int64 a4) {
    __int64 v10;
    __int64 v5;
    __int64 result;
    __int64 v3;
    __int64 v4;
    __int64 *src;
    __int64 i;
    int v6;
    __int64 v8;
    __int64 v7;

    a4 = 0;
    v10 = a3;
    v10 -= 15;
    if (v10 >= 0) a4 = v10;
    if (a3 != 0) {
        v5 = a2 + 7;
        v5 &= -8;
        v5 -= (__int64)a2;
        result = 0;
        v3 = &off_1401133CD;
        v4 = 0x8080808080808080;
        do {
            src = *(a2 + v10);
            i = *(src + v3);
            v6 = 1;
            if (i == 4) {
                v8 = v10 + 1;
                if (v8 >= a3) JUMPOUT(0x140017d33);
                i = *(a2 + v8);
                if (src == 240) {
                    i += 112;
                    if (i < 48) {
                        src = v10 + 2;
                        if (src >= a3) JUMPOUT(0x140017d33);
                        if (*(__int64 *)((__int64)a2 + (__int64)src) > 191) JUMPOUT(0x140017d3c);
                        i = v10 + 3;
                        if (i >= a3) JUMPOUT(0x140017d33);
                        if (*(a2 + i) < 192) {
                            ++i;
                            v10 = i;
                            *(a1 + 8) = a2;
                            a1[2] = a3;
                            result = 0;
                            return sub_140017D4E();
                        }
                        src = 3;
                        return sub_140017D3E();
                    }
                    return sub_140017D38();
                }
                if (src != 244) {
                    src += 15;
                    if (src > 2) JUMPOUT(0x140017d38);
                    if (i >= 192) JUMPOUT(0x140017d38);
                    return (__int64)src;
                }
                if (i <= 143) {
                    return (__int64)src;
                }
                return sub_140017D38();
            }
            if (i == 3) {
                v7 = v10 + 1;
                if (v7 >= a3) JUMPOUT(0x140017d33);
                i = *(a2 + v7);
                if (src == 224) {
                    i &= 224;
                    if (i == 160) {
                        i = v10 + 2;
                        if (i >= a3) JUMPOUT(0x140017d33);
                        if (*(a2 + i) <= 191) {
                            return i;
                        }
                        return sub_140017D3C();
                    }
                    return sub_140017D38();
                }
                if (src != 237) {
                    v10 = src + 31;
                    if (v10 < 12) {
                        if (i >= 192) JUMPOUT(0x140017d38);
                        return v10;
                    }
                    src = (__int64 *)((__int64)(__int64)src & 254);
                    if (src != 238) JUMPOUT(0x140017d38);
                    return (__int64)src;
                }
                if (i <= 159) {
                    return (__int64)src;
                }
                return sub_140017D38();
            }
            if (i != 2) JUMPOUT(0x140017d38);
            i = v10 + 1;
            if (i >= a3) JUMPOUT(0x140017d33);
            src = 1;
            if (*(a2 + i) <= 191) {
                return (__int64)src;
            }
            return sub_140017D3E();
        } while (v10 < a3);
    }
    return result;
}