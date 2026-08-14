__int64 sub_1400377D0();
__int64 sub_140037910();
__int64 sub_140037C60();

__int64 __fastcall sub_1400411B0(__int64 a1) {
    int v_10;
    int v_18;
    int v_8;
    __int64 *src;
    __int64 *dst;
    __int64 v3;

    v_8 = -2;
    v_18 = a1;
    a1 += 24;
    v_10 = a1;
    sub_1400377D0(a1);
    src = (__int64 *)v_10;
    dst = *src;
    if (dst != 0) {
        *dst = *dst - 1;
        if (!((*dst != 0))) {
            sub_140037910(src);
        }
    }
    v3 = v_18;
    return sub_140037C60();
}