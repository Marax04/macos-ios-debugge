__int64 sub_1400F457C();
__int64 off_140108030();
__int64 off_140108078();

__int64 __fastcall sub_1400F44F0(__int64 a1, __int64 a2, __int64 a3, __int64 a4) {
    __int64 *dst;
    __int64 v4;
    __int64 v1;
    __int64 v5;
    int v6;
    __int64 v2;

    dst = (__int64 *)a1;
    v4 =  + a4*8;
    a4 >>= 61;
    v1 = (a4 != 0) ? 1 : 0;
    v5 = 0x7FFFFFFFFFFFFFF8;
    a1 = (v4 > v5) ? 1 : 0;
    a1 |= v1;
    v6 = 1;
    if ((a1 == 0)) {
        if (a2 == 0) JUMPOUT(0x1400f4560);
        v2 = a3;
        off_140108030(v5, a2, a3, a4);
        off_140108078(v1, 0, a3, v4);
        if (v1 == 0) JUMPOUT(0x1400f456f);
        *(dst + 8) = v1;
        v1 = 16;
        v6 = 0;
        return sub_1400F457C();
    } else {
        v1 = 8;
        v4 = 0;
        return sub_1400F457C();
    }
}