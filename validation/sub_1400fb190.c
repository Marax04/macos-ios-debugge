__int64 sub_1400FB201();
__int64 off_140108030();
__int64 off_140108078();

__int64 __fastcall sub_1400FB190(__int64 a1, __int64 a2, __int64 a3, __int64 a4) {
    __int64 *dst;
    int v5;
    __int64 v4;
    __int64 v2;
    __int64 v1;

    dst = (__int64 *)a1;
    v5 = 1;
    if (a4 >= 0) {
        v4 = a4;
        if (a2 == 0) JUMPOUT(0x1400fb1e5);
        v2 = a3;
        off_140108030(8);
        off_140108078(v1, 0, a3, v4);
        if (v1 == 0) JUMPOUT(0x1400fb1f4);
        *(dst + 8) = v1;
        v1 = 16;
        v5 = 0;
        return sub_1400FB201();
    } else {
        v4 = 0;
        return sub_1400FB201();
    }
}