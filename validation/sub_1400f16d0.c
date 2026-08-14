__int64 sub_1400F17C1();
__int64 sub_1400F17E7();
__int64 sub_1400F17E2();

__int64 __fastcall sub_1400F16D0(__int64 *a1, int a2, __int64 a3, __int64 a4) {
    __int64 *src;
    __int64 v6;
    __int64 v4;
    __int64 v5;
    __int64 v2;
    __int64 v8;
    __int64 v1;
    __int64 v9;
    __int64 v7;

    src = *(a1 + 8);
    v6 = a1[2];
    if (v6 > 16) {
        v4 = v6 - 17;
        v5 = 0xA4093822299F31D0;
        if (v4 >= 16) JUMPOUT(0x1400f1769);
        v2 = 0x13198A2E03707344;
        v8 = 0x243F6A8885A308D3;
        return sub_1400F17C1();
    } else {
        if (v6 <= 7) {
            if (v6 <= 3) JUMPOUT(0x1400f1948);
            v1 = *src;
            a2 = *(src + v6 - 4);
            v9 = 0x243F6A8885A308D3;
            v9 ^= v1;
            v7 = 0x13198A2E03707344;
            v7 ^= a2;
            return sub_1400F17E7();
        } else {
            a4 = 0x243F6A8885A308D3;
            a4 ^= *src;
            a3 = 0x13198A2E03707344;
            return sub_1400F17E2();
        }
    }
}