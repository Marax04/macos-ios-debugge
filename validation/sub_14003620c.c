__int64 off_1401080F0();
__int64 off_140108158();
__int64 off_140108060();

__int64 __fastcall sub_14003620C(__int64 a1, int a2, __int64 a3, __int64 a4) {
    int arg_3c8;
    int arg_3e8;
    int arg_3f8;
    int arg_400;
    __int64 v6;
    __int64 result;
    __int64 v2;
    __int64 v7;
    int v5;
    __int64 v4;
    __int64 v3;

    v6 = 512;
    result = 2;
    arg_400 = result;
    arg_3c8 = 0;
    v2 = 0;
    v7 = 0;
    if (v6 < 513) {
        v5 = 512;
        v4 = v6;
    }
    do {
        v6 -= v7;
        v2 -= v7;
        if (v6 > v2) JUMPOUT(0x14003630c);
        result = 0xFFFFFFFF;
        v2 = arg_3c8;
        v7 = 0xFFFFFFFF;
        if (v2 < result) v7 = v2;
        arg_3e8 = v7;
        v3 = arg_400;
        v4 = v7;
        do {
            off_1401080F0(0);
            a1 = arg_3f8;
            off_140108158(a1, a2, a3, 0);
            v6 = result;
            if (v4 != v6) {
                if ((0 /* unresolved: flags >= */)) JUMPOUT(0x140036355);
                return v6;
            }
            off_140108060();
            if (result != 122) JUMPOUT(0x14003651f);
            v4 += v4;
            result = 0xFFFFFFFF;
            if (v4 >= result) v4 = result;
            v6 = v4;
            if (v4 < 513) {
                return result;
            }
        } while (true);
    } while (v6 >= 513);
}