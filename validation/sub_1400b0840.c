__int64 sub_1400F1D90();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400B91D0();
__int64 sub_1400F3326();
__int64 sub_1400B098D();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400B0840(int a1, int a2) {
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
    v4 = 0xF4240;
    if (a2 < 0xF4240) v4 = a2;
    if (v4 <= v7) v4 = v7;
    v2 = 48;
    if (v4 >= 49) v2 = v4;
    if (v4 >= 513) {
        v3 =  + v2*8;
        v7 >>= 61;
        result = (v7 == 0) ? 1 : 0;
        v6 = 0x7FFFFFFFFFFFFFFD;
        v4 = (v3 < v6) ? 1 : 0;
        if ((result & v4) == 0) {
            sub_1400F3360(a1, a2, v6);
        }
        v9 = a1;
        v10 = a2;
        sub_14002EDF0(0, v3);
        if (v7 != 0) {
            v_20 = (v10 < 65) ? 1 : 0;
            sub_1400B91D0(v9, v10, v7, v2);
            off_140108030();
            a1 = v7;
            a2 = 0;
            JUMPOUT(off_140108038);
        }
        sub_1400F3326(4, v3, v7);
        v8 = a1 + a2*8;
        v5 = a1 + 8;
        a2 = 8;
        return sub_1400B098D();
    } else {
        v_20 = (a2 < 65) ? 1 : 0;
        sub_1400B91D0(a1, a2, str, 512);
        return result;
    }
}