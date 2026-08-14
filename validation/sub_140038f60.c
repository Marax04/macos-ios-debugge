__int64 sub_1400377D0();
__int64 sub_140037910();

__int64 __fastcall sub_140038F60(__int64 a1) {
    int v_10;
    int v_8;
    __int64 *src;
    __int64 *result;

    v_8 = -2;
    v_10 = a1;
    sub_1400377D0();
    src = (__int64 *)v_10;
    result = *src;
    if (result != 0) {
        *result = *result - 1;
        if (!((*result != 0))) {
            return sub_140037910();
        }
    }
    return (__int64)result;
}