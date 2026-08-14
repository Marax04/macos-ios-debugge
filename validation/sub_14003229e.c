__int64 sub_14002D130();

__int64 __fastcall sub_14003229E(__int64 *a1, __int64 a2, __int64 a3) {
    __int64 arg_100;
    int arg_13f;
    int arg_50;
    int arg_f8;
    char *str;
    char *str2;
    __int64 v3;
    __int64 v2;
    __int64 *dst;

    a1 += *(dst + 0xEA85);
    *(dst - 115) = *(dst - 115) + a1;
    if ((*(dst - 115) != 0)) JUMPOUT(0x1400322fa);
    v3 = 0;
    do {
        arg_13f = 0;
        sub_14002D130(str, str2);
        v2 = arg_50;
        if (v2 == 10) JUMPOUT(0x14003241b);
        dst = (__int64 *)v2;
        dst -= 5;
        if (v2 < 6) dst = v3;
        if (dst == 1) JUMPOUT(0x140032377);
        if (dst != 3) JUMPOUT(0x1400323b7);
        dst = (__int64 *)arg_100;
        a2 = (dst == 0) ? 1 : 0;
        a1 = (__int64)(__int64)dst * 56;
        a1 += arg_f8;
        a1 -= 56;
        a3 = (a1 == 0) ? 1 : 0;
        a3 |= a2;
        --dst;
        arg_100 = (__int64)dst;
    } while (*a1 != 9);
}