__int64 sub_14002E290();
__int64 sub_1400354E5();
__int64 sub_14003558B();

__int64 __fastcall sub_140035460(__int64 a1) {
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    char *str;
    __int64 v2;
    __int64 v5;
    __int64 v7;
    __int64 v9;
    __int64 v8;
    __int64 v4;
    __int64 v6;
    __int64 v3;

    v2 = a1;
    v5 = str - 64;
    sub_14002E290(v5);
    v7 = v_40;
    v7 = -v7;
    if ((0 /* overflow check on (-v7) */)) {
        v9 = v_38;
        v8 = v_30;
        if ((v_28 & 1) != 0) JUMPOUT(0x140035559);
        if (v8 == 0) JUMPOUT(0x140035559);
        v4 = v9 + v8;
        v6 = v9 + 1;
        return sub_1400354E5();
    } else {
        v3 = 0x8000000000000000;
        return sub_14003558B();
    }
}