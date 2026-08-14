__int64 off_1401080F0();
__int64 off_140108148();
__int64 off_140108060();

__int64 __fastcall sub_14002E394(__int64 a1) {
    int arg_3f0;
    int arg_3f8;
    int arg_408;
    int arg_418;
    __int64 v6;
    __int64 result;
    __int64 v4;
    __int64 v5;
    __int64 v8;
    int v9;
    __int64 v7;
    __int64 v2;
    __int64 v3;

    arg_3f0 = 2;
    arg_3f8 = 0;
    v6 = 512;
    result = 2;
    arg_418 = result;
    v4 = 0;
    v5 = 0;
    v8 = 0;
    if (v6 < 513) {
        v9 = 512;
        v7 = v6;
    }
    do {
        v6 -= v8;
        v5 -= v8;
        if (v6 > v5) JUMPOUT(0x14002e496);
        result = 0xFFFFFFFF;
        v8 = 0xFFFFFFFF;
        if (v4 < result) v8 = v4;
        arg_3f8 = v8;
        v5 = v4;
        v2 = arg_418;
        v7 = v8;
        do {
            off_1401080F0(0, v3, v6);
            a1 = arg_408;
            off_140108148(a1, v3, v7);
            v2 = result;
            if (v7 != v6) {
                if ((0 /* unresolved: flags >= */)) JUMPOUT(0x14002e4ce);
                return v2;
            }
            off_140108060(a1, v3, v2);
            if (result != 122) JUMPOUT(0x14002e686);
            v7 += v7;
            result = 0xFFFFFFFF;
            if (v7 >= result) v7 = result;
            v6 = v7;
            if (v7 < 513) {
                return result;
            }
        } while (true);
    } while (v6 >= 513);
}