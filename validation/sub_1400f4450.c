__int64 sub_1400F4480();
__int64 sub_1400F3326();
__int64 sub_1400F44F0();

__int64 __fastcall sub_1400F4450(__int64 *a1) {
    int v_28;
    int v_30;
    char *str;
    __int64 i;
    __int64 *src;
    __int64 *src2;
    __int64 v7;
    __int64 v9;
    __int64 v5;
    __int64 v6;
    __int64 result;
    __int64 v3;
    __int64 v2;

    i = *a1;
    sub_1400F4480(a1, i);
    src = 0x8000000000000001;
    if (v2 != src) {
        sub_1400F3326(v2);
        src2 = src;
        ++i;
        v7 = *src;
        v9 = v7 + v7;
        if (i <= v9) i = v9;
        v5 = 4;
        if (i >= 5) v5 = i;
        v6 = *(src2 + 8);
        sub_1400F44F0(str, v7, v6);
        if (str == 0) JUMPOUT(0x1400f44d3);
        result = v_28;
        v3 = v_30;
        return v3;
    } else {
        return result;
    }
}