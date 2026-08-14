__int64 sub_1400F44F0();

__int64 __fastcall sub_1400F4480(__int64 *a1, int a2) {
    int v_28;
    int v_30;
    char *str;
    __int64 *dst;
    __int64 v2;
    __int64 v8;
    __int64 v4;
    __int64 v5;
    __int64 v7;
    __int64 result;
    __int64 v6;
    __int64 v9;

    dst = a1;
    ++a2;
    v2 = *a1;
    v8 = v2 + v2;
    if (a2 <= v8) a2 = v8;
    v4 = 4;
    if (a2 >= 5) v4 = a2;
    v5 = *(dst + 8);
    sub_1400F44F0(str, v2, v5);
    if (str == 0) {
        v7 = v_28;
        *(dst + 8) = v7;
        *dst = v4;
        result = 0x8000000000000001;
        return result;
    } else {
        v6 = v_28;
        v9 = v_30;
        return result;
    }
}