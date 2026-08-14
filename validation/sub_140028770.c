__int64 sub_140028A80();
__int64 off_1401080A8();
__int64 off_1401080B0();
__int64 off_1401080B8();
__int64 off_140108060();

__int64 __fastcall sub_140028770(__int64 a1, int a2, __int64 a3, __int64 a4) {
    int arg_28;
    int v_38;
    int str;
    char *str2;
    __int64 result;
    __int64 v2;
    __int64 v3;
    __int64 v4;

    arg_28 = -2;
    if (a3 == 0) {
        a2 = 0;
        result = 0;
    } else {
        v2 = a2;
        v3 = a3;
        off_1401080A8();
        v4 = result;
        if (v4 == 0) {
            a2 = 0x600000002;
        } else {
            if (v4 != -1) {
                str = 0;
                a2 = str2 - 8;
                off_1401080B0(v4, a2);
                if (result != 0) {
                    off_1401080B8();
                    if (result != 0xFDE9) JUMPOUT(0x140028828);
                }
                str = v4;
                a1 = str2 - 8;
                v_38 = v4;
                sub_140028A80(a1, v2, v3);
            } else {
                off_140108060(1);
                a2 = result;
                result = 1;
                a2 <<= 32;
                a2 |= 2;
            }
        }
    }
    return result;
}