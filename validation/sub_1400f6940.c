__int64 sub_1400F69D8();
__int64 sub_1400F69F2();
__int64 off_140108030();
__int64 off_140108078();

__int64 __fastcall sub_1400F6940(__int64 a1, __int64 a2, __int64 a3, __int64 a4) {
    int arg_60;
    int arg_68;
    __int64 v5;
    __int64 v3;
    __int64 v10;
    __int64 v6;
    __int64 v8;
    __int64 v7;
    __int64 v4;
    int v1;
    __int64 v9;
    __int64 v2;

    v5 = a2;
    v3 = a1;
    v10 = arg_60;
    v6 = arg_68;
    v8 = v10 + v6;
    --v8;
    v7 = v10;
    v7 = -v7;
    v7 &= v8;
    v7 *= a4; /* unsigned; high half in a2 */;
    v4 = v7;
    v1 = (0 /* overflow check on (v7 & v8) */) ? 1 : 0;
    v9 = 0x8000000000000000;
    v9 -= v10;
    a1 = (v4 > v9) ? 1 : 0;
    a1 |= v1;
    v9 = 1;
    if ((a1 == 0)) {
        if (v5 == 0) JUMPOUT(0x1400f69c4);
        v2 = a3;
        off_140108030(v9);
        off_140108078(v7, 0, a3, v4);
        if (v7 != 0) JUMPOUT(0x1400f69e6);
        return sub_1400F69D8();
    } else {
        v1 = 8;
        v4 = 0;
        return sub_1400F69F2();
    }
}