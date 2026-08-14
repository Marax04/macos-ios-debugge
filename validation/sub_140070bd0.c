__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_140071090();
__int64 sub_140070D2F();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140070BD0(int a1, int a2) {
    int v_10;
    int v_20;
    int v_8;
    __int64 v8;
    __int64 v5;
    __int64 result;
    __int64 v3;
    __int64 v2;
    __int64 v4;
    __int64 v10;
    __int64 v6;
    __int64 v11;
    __int64 v7;
    __int64 v9;

    v8 = a2;
    v8 >>= 1;
    v5 = a2;
    v5 -= v8;
    result = 0x1631D;
    if (a2 < 0x1631D) v8 = a2;
    if (v8 <= v5) v8 = v5;
    v3 = 48;
    if (v8 >= 49) v3 = v8;
    if (v5 >= v8) {
        sub_1400F3360(0x1745D1745D1745E, a1, a2, v5);
    }
    v2 = v3 * 88;
    if (v2 != 0) {
        v4 = a1;
        v10 = a2;
        sub_14002EDF0(0, v2);
        a1 = v4;
        a2 = v10;
        v4 = v8;
        if (v8 == 0) {
            sub_1400F3326(8, v2);
            v4 = 8;
            v3 = 0;
        }
        v_20 = (a2 < 65) ? 1 : 0;
        sub_140071090(a1, a2, v4);
        off_140108030();
        a1 = v8;
        a2 = 0;
        v6 = v4;
        JUMPOUT(off_140108038);
        v11 = a1;
        v7 = a2 * 88;
        v7 += a1;
        v9 = a1 + 88;
        a2 = 0;
        v5 = 2;
        v4 = 0;
        v_8 = a1;
        v_10 = v7;
        return sub_140070D2F();
    }
    return result;
}