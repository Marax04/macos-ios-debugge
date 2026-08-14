__int64 sub_140028770();
extern __int64 off_1401213C0;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400282A0(int a1, int a2, __int64 a3) {
    char *dst;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 v7;
    __int64 v6;
    __int64 v5;
    __int64 result;

    *dst = -2;
    if (a3 != 0) {
        v3 = a3;
        v4 = a2;
        v2 = a1;
        v7 = &off_1401213C0;
        v6 = off_140108030;
        v5 = off_140108038;
        do {
            sub_140028770(0xFFFFFFF4, v4, v3);
            if (a2 == 0) JUMPOUT(0x1400283de);
            result = v3;
            result -= a2;
            if ((result < 0)) JUMPOUT(0x1400283e7);
            v4 += a2;
            v3 = result;
        } while (v3 != 0);
    }
    a2 = 0;
    result = a2;
    return result;
}