__int64 sub_1400F1D90();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_14009A360();
__int64 sub_1400F3326();
__int64 sub_14009A30D();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14009A1C0(int a1, int a2) {
    int v_20;
    char *str;
    __int64 v4;
    __int64 v7;
    __int64 v2;
    __int64 v3;
    __int64 result;
    __int64 v6;
    __int64 v9;
    __int64 v10;
    __int64 v8;
    __int64 v5;

    sub_1400F1D90(0x1030);
    v4 = a2;
    v4 >>= 1;
    v7 = a2;
    v7 -= v4;
    v4 = 0x1E8480;
    if (a2 < 0x1E8480) v4 = a2;
    if (v4 <= v7) v4 = v7;
    v2 = 48;
    if (v4 >= 49) v2 = v4;
    if (v4 >= 0x401) {
        v3 =  + v2*4;
        v7 >>= 62;
        result = (v7 == 0) ? 1 : 0;
        v6 = 0x7FFFFFFFFFFFFFFF;
        v4 = (v3 < v6) ? 1 : 0;
        if ((result & v4) == 0) {
            sub_1400F3360(a1, a2, v6);
        }
        v9 = a1;
        v10 = a2;
        sub_14002EDF0(0, v3);
        if (v7 != 0) {
            v_20 = (v10 < 65) ? 1 : 0;
            sub_14009A360(v9, v10, v7, v2);
            off_140108030();
            a1 = v7;
            a2 = 0;
            JUMPOUT(off_140108038);
        }
        sub_1400F3326(2, v3, v7);
        v8 = a1 + a2*4;
        v5 = a1 + 4;
        a2 = 4;
        return sub_14009A30D();
    } else {
        v_20 = (a2 < 65) ? 1 : 0;
        sub_14009A360(a1, a2, str, 0x400);
        return result;
    }
}