__int64 off_140108060();
extern __int64 off_1401080F0;
extern __int64 off_1401080F8;

__int64 __fastcall sub_14002A168(int a1) {
    int arg_3c8;
    int arg_3d0;
    int arg_3d8;
    int arg_3f0;
    int arg_3f8;
    __int64 v6;
    __int64 result;
    __int64 v9;
    __int64 v5;
    __int64 v10;
    __int64 v4;
    __int64 v2;
    __int64 v8;
    __int64 v7;
    __int64 v3;

    arg_3f0 = 2;
    arg_3f8 = 0;
    v6 = 512;
    result = 2;
    arg_3d0 = result;
    arg_3d8 = 0;
    v9 = off_1401080F0;
    v5 = off_1401080F8;
    v10 = 0xFFFFFFFF;
    v4 = 0;
    v2 = 0;
    if (v6 < 513) {
        result = 512;
        arg_3c8 = result;
        v8 = v6;
    }
    do {
        v6 -= v2;
        v4 -= v2;
        if (v6 > v4) JUMPOUT(0x14002a29d);
        v4 = arg_3d8;
        v2 = 0xFFFFFFFF;
        if (v4 < v10) v2 = v4;
        arg_3f8 = v2;
        arg_3c8 = v2;
        v7 = arg_3d0;
        v8 = v2;
        do {
            ((__int64 (*)())v9)(0, v3, v6);
            ((__int64 (*)())v5)(v8);
            if (v8 != v6) {
                if ((0 /* unresolved: flags >= */)) JUMPOUT(0x14002a2dc);
                return v8;
            }
            off_140108060(result, v3, result);
            if (result != 122) JUMPOUT(0x14002a399);
            v8 += v8;
            if (v8 >= v10) v8 = v10;
            v6 = v8;
            if (v8 < 513) {
                return result;
            }
        } while (true);
    } while (true);
}