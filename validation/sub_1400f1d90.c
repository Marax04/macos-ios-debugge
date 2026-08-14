__int64 __fastcall sub_1400F1D90() {
    __int64 rsp;
    int v_8;
    __int64 v4;
    __int64 v2;
    __int64 *dst;
    __int64 v5;
    __int64 v3;
    __int64 v8;
    __int64 v6;
    __int64 v1;

    *(__int64 *)rsp = v5;
    v_8 = v6;
    v4 = 0;
    v2 = rsp + 24;
    v2 -= v1;
    if (v2 < 0) v2 = v4;
    dst = __readgsqword(16);
    if (v2 < dst) {
        v5 &= 0xF000;
        do {
            dst -= 0x1000;
            *dst = 0;
        } while (v2 != dst);
    }
    v3 = *(__int64 *)rsp;
    v8 = v_8;
    return v8;
}