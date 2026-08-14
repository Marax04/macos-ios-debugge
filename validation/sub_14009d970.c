__int64 sub_14002EDF0();
__int64 sub_1400F3326();

__int64 __fastcall sub_14009D970(int a1) {
    __int64 v4;
    __int64 v2;
    __int64 v5;
    __int64 v3;
    __int64 result;

    if (a1 != 0) {
        v4 = a1;
        v2 = a1 + a1*8;
        v5 = v2 + v2*2;
        v5 += a1;
        sub_14002EDF0(0, v5);
        v3 = v2;
        if (v2 == 0) {
            sub_1400F3326(4, v5);
            v3 = 4;
            v4 = 0;
        }
        result = v4;
        return result;
    }
    return result;
}