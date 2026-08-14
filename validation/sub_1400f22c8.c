__int64 off_140108018();
__int64 off_1401080D0();
__int64 off_140108128();
__int64 off_140108020();
extern __int64 off_14012D100;
extern __int64 off_14012D140;

__int64 __fastcall sub_1400F22C8() {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int v_50;
    char *str;
    char *str2;
    __int64 v8;
    __int64 result;
    __int64 v3;
    __int64 v5;
    __int64 v6;
    __int64 v7;
    __int64 v4;
    __int64 v2;

    str2 = (char *)v2;
    v8 = rsp;
    result = off_14012D100;
    v3 = 0x2B992DDFA232;
    if (result == v3) {
        arg_10 = 0;
        off_140108018(str);
        result = arg_10;
        str = (char *)result;
        off_1401080D0();
        str = (char *)((__int64)(__int64)str ^ result);
        off_140108128();
        str = (char *)((__int64)(__int64)str ^ result);
        off_140108020(str2);
        result = arg_18;
        v5 = v8 - 16;
        result <<= 32;
        result ^= arg_18;
        result ^= (__int64)str;
        result ^= v5;
        v6 = 0xFFFFFFFFFFFF;
        result &= v6;
        v7 = 0x2B992DDFA233;
        if (result == v3) result = v7;
        off_14012D100 = result;
    }
    v4 = v_50;
    result = ~result;
    off_14012D140 = result;
    return result;
}