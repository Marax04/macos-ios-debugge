__int64 sub_1400F3473();
__int64 sub_1400F3493();
__int64 off_140108030();
__int64 off_140108078();

__int64 __fastcall sub_1400F3410(__int64 a1, __int64 a2, __int64 a3, __int64 a4) {
    int v4;
    __int64 v3;
    __int64 v2;
    __int64 v1;

    v4 = 1;
    if (a4 >= 0) {
        v3 = a4;
        if (a2 == 0) JUMPOUT(0x1400f345f);
        v2 = a3;
        off_140108030(8);
        off_140108078(v1, 0, a3, v3);
        if (v1 != 0) JUMPOUT(0x1400f3487);
        return sub_1400F3473();
    } else {
        v3 = 0;
        return sub_1400F3493();
    }
}