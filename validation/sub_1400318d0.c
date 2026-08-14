__int64 sub_140030C50();
__int64 sub_140028A80();
__int64 off_140108048();
extern __int64 off_140121A40;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400318D0(__int64 a1, int a2, __int64 a3, __int64 a4) {
    int v_20;
    int v_24;
    int v_25;
    int v_27;
    int v_2c;
    int v_30;
    int v_38;
    int v_40;
    char *dst;
    __int64 v3;
    __int64 v4;
    __int64 v2;
    __int64 v7;
    __int64 v6;
    __int64 v5;
    __int64 result;

    *dst = -2;
    v3 = a4;
    v4 = a3;
    v_40 = 0;
    v_38 = 0;
    v_30 = 7;
    v_2c = 0;
    v_25 = 0;
    v_27 = 1;
    v_24 = 1;
    v_25 = 1;
    a3 = dst - 64;
    sub_140030C50(a1, a2, a3);
    if ((result & 1) == 0) {
        v_20 = a2;
        v_40 = a2;
        if (v3 != 0) {
            v2 = dst - 64;
            v7 = &off_140121A40;
            v6 = off_140108030;
            v5 = off_140108038;
            do {
                sub_140028A80(v2, v4, v3);
                if (a2 == 0) JUMPOUT(0x140031a6c);
                result = v3;
                result -= a2;
                if ((result < 0)) JUMPOUT(0x140031a75);
                v4 += a2;
                v3 = result;
            } while (v3 != 0);
        }
        a1 = v_20;
        v3 = a2;
        off_140108048(a1, 0);
        a2 = v3;
    }
    result = a2;
    return result;
}