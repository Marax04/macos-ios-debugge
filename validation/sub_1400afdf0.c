__int64 sub_1400F1D90();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400BA460();
__int64 sub_1400AFF3E();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400AFDF0(int a1, int a2) {
    int v_20;
    char *str;
    __int64 v4;
    __int64 v7;
    __int64 v2;
    __int64 v8;
    __int64 v1;
    __int64 v3;
    __int64 v9;
    __int64 v6;
    __int64 v10;
    __int64 v5;

    sub_1400F1D90(0x1028);
    v4 = a2;
    v4 >>= 1;
    v7 = a2;
    v7 -= v4;
    v4 = 0x30D40;
    if (a2 < 0x30D40) v4 = a2;
    if (v4 <= v7) v4 = v7;
    v2 = 48;
    if (v4 >= 49) v2 = v4;
    if (v4 >= 103) {
        if (v7 >= v4) {
            sub_1400F3360(a1, a2, 0x333333333333334);
        }
        v8 =  + v2*8;
        v1 = v8 + v8*4;
        if (v1 != 0) {
            v3 = a1;
            v9 = a2;
            sub_14002EDF0(0, v1);
            a1 = v3;
            a2 = v9;
            v3 = v8;
            if (v8 == 0) {
                sub_1400F3326(8, v1);
                v3 = 8;
                v2 = 0;
            }
            v_20 = (a2 < 65) ? 1 : 0;
            sub_1400BA460(a1, a2, v3, v2);
            off_140108030();
            a1 = v8;
            a2 = 0;
            v6 = v3;
            JUMPOUT(off_140108038);
            v10 = a2 + a2*4;
            v10 = a1 + v10*8;
            v5 = a1 + 40;
            a2 = 40;
            return sub_1400AFF3E();
        }
        return a2;
    } else {
        v_20 = (a2 < 65) ? 1 : 0;
        sub_1400BA460(a1, a2, str, 102);
        return v_20;
    }
}