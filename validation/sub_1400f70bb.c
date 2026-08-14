__int64 sub_1400F4590();
__int64 sub_1400F6DC0();
extern __int64 off_14012D060;
extern __int64 off_14012D028;
extern __int64 off_140113AE0;
extern __int64 off_140113AB8;

__int64 __fastcall sub_1400F70BB(__int64 a1) {
    int arg_10;
    int arg_8;
    int v_20;
    char *str;
    __int64 result;
    __int64 *dst;
    __int64 v3;
    __int64 v4;
    __int64 *dst2;
    __int64 v7;
    __int64 v6;

    sub_1400F4590();
    result = off_14012D060;
    if (result != 0) {
        dst = str - 40;
        *dst = a1;
        v3 = &off_14012D028;
        arg_8 = v3;
        v4 = str - 1;
        arg_10 = v4;
        dst2 = str - 16;
        *dst2 = dst;
        result = &off_140113AE0;
        v_20 = result;
        v7 = &off_14012D060;
        v6 = &off_140113AB8;
        sub_1400F6DC0(v7, 1, dst2, v6);
    }
    return result;
}