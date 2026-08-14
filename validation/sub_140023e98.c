__int64 sub_14001A580();
__int64 sub_140021AD5();
__int64 sub_140023FD7();
extern __int64 off_14011D528;

__int64 __fastcall sub_140023E98(__int64 a1, __int64 a2) {
    int arg_18;
    int arg_20;
    int v_20;
    char *str;
    __int64 v3;
    __int64 v6;
    __int64 v2;
    __int64 v10;
    __int64 v7;
    __int64 v9;
    __int64 v8;
    int v1;
    __int64 v5;

    v3 = a2;
    v_20 = 1;
    v6 = &off_14011D528;
    v2 = str - 80;
    sub_14001A580(v2, a1, v5, v6);
    v10 = str + 24;
    do {
        sub_140021AD5(v10, v2);
        v7 = arg_18;
    } while (v7 == 0);
    if (v1 != 1) {
        v9 = v3;
    } else {
        v9 = arg_20;
    }
    v8 = v3;
    v8 -= v9;
    if (v8 <= 16) JUMPOUT(0x140023f0e);
    v1 = 0;
    return sub_140023FD7();
}