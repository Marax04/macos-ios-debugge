__int64 sub_1400F589F();
__int64 sub_1400F58BF();
__int64 off_140108030();
__int64 off_140108078();

__int64 __fastcall sub_1400F5820(__int64 a1, __int64 a2, __int64 a3, __int64 a4) {
    int v_70;
    __int64 v5;
    __int64 v3;
    __int64 v1;
    __int64 v4;
    __int64 v6;
    int v7;
    __int64 v2;

    v5 = a2;
    v3 = a1;
    v1 = v_70;
    v1 += 7;
    v1 &= 120;
    v1 *= a4; /* unsigned; high half in a2 */;
    v4 = v1;
    v1 = (0 /* overflow check on (v1 & 120) */) ? 1 : 0;
    v6 = 0x7FFFFFFFFFFFFFF8;
    a1 = (v4 > v6) ? 1 : 0;
    a1 |= v1;
    v7 = 1;
    if ((a1 == 0)) {
        if (v5 == 0) JUMPOUT(0x1400f588b);
        v2 = a3;
        off_140108030(v6);
        off_140108078(v1, 0, a3, v4);
        if (v1 != 0) JUMPOUT(0x1400f58b3);
        return sub_1400F589F();
    } else {
        v1 = 8;
        v4 = 0;
        return sub_1400F58BF();
    }
}