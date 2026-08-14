__int64 sub_140099E40();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14009C450(__int64 a1) {
    int v_38;
    char *str;
    __int64 v3;
    __int64 v5;
    __int64 v6;
    __int64 *result;
    __int64 v4;
    __int64 v2;

    v3 = a1;
    v5 = off_140108030;
    v6 = off_140108038;
    sub_140099E40(str);
    result = (__int64 *)str;
    while (result != 0) {
        v4 = v_38;
        v4 += v4*2;
        result += v4*8;
        result += 8;
        v2 = *(result + 8);
        ((__int64 (*)())v5)(v4);
        ((__int64 (*)())v6)(result, 0);
    }
    return (__int64)result;
}