__int64 sub_140028050();
extern __int64 off_140029BA0;
extern __int64 off_1401175D8;

__int64 __fastcall sub_140029B40(__int64 a1, __int64 a2) {
    int v_1;
    int v_10;
    int v_18;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    char *str;
    __int64 v1;
    __int64 v2;
    __int64 v3;
    __int64 v4;

    v_1 = a2;
    v1 = str - 1;
    v_18 = v1;
    v2 = &off_140029BA0;
    v_10 = v2;
    v3 = &off_1401175D8;
    v_48 = v3;
    v_40 = 1;
    v_28 = 0;
    v4 = str - 24;
    v_38 = v4;
    v_30 = 1;
    a2 = str - 72;
    return sub_140028050(a1, a2);
}