__int64 sub_14002EDF0();
__int64 sub_1400F27FC();
__int64 off_140108158();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_140040080(__int64 *a1, __int64 a2, __int64 a3, __int64 a4) {
    __int64 v5;
    __int64 v6;
    __int64 v4;
    __int64 v2;
    __int64 v3;
    __int64 v7;
    __int64 result;

    v5 = 0xFFFFFFFF00000000;
    v5 += a2;
    if (v5 >= a3) {
        if (*(a1 + a2*2 - 2) == 0) {
            v6 = (__int64)a1;
            v4 = a2;
            v2 = a2 + a2;
            sub_14002EDF0(0, v2, 0xFFFFFFFF00000001);
            if (v5 == 0) JUMPOUT(0x140040135);
            v3 = v5;
            v7 = v4 - 1;
            v4 = 0;
            off_140108158(v6, v4, v5, 0);
            a1 = (result == 0) ? 1 : 0;
            result = (v7 != v5) ? 1 : 0;
            result |= (__int64)a1;
            if (!((result != 0))) {
                sub_1400F27FC(v6, v3, v2);
                v4 = (result == 0) ? 1 : 0;
            }
            off_140108030();
            off_140108038(v5, 0, v3);
        } else {
            v4 = 0;
        }
        result = v4;
        return result;
    }
    return result;
}