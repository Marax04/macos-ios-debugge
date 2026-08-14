__int64 sub_1400A7562();

__int64 __fastcall sub_1400A7574() {
    __int64 *dst;
    __int64 v7;
    __int64 v3;
    __int64 *dst2;
    __int64 v4;
    __int64 v6;
    __int64 v5;
    __int64 v9;
    __int64 v8;

    dst -= 173;
    *dst = *dst + (__int64)dst;
    *dst = *dst + (__int64)dst;
    v7 += v9;
    if (v9 == 0) JUMPOUT(0x1400a7513);
    v3 = dst + v7*8;
    v3 -= 40;
    if (v3 == 0) JUMPOUT(0x1400a7513);
    dst2 = dst + v7*8;
    v4 = *(dst2 - 8);
    v6 = *(dst2 - 16);
    v6 += v4;
    if (v8 > v6) JUMPOUT(0x1400a7513);
    if (v5 <= v6) JUMPOUT(0x1400a7562);
    v5 -= v4;
    *(dst2 - 16) = v5;
    return sub_1400A7562();
}