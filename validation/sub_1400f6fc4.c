__int64 sub_1400F6DC0();
extern __int64 off_14012D060;
extern __int64 off_14012D028;
extern __int64 off_140113AE0;
extern __int64 off_140113B20;

__int64 __fastcall sub_1400F6FC4() {
    int arg_8;
    int v_20;
    char *str;
    __int64 result;
    __int64 v2;
    __int64 *dst;
    __int64 v4;
    __int64 *dst2;
    __int64 v5;
    __int64 v7;

    result = off_14012D060;
    if (result != 0) {
        v2 = &off_14012D028;
        dst = str - 32;
        *dst = v2;
        v4 = str - 1;
        arg_8 = v4;
        dst2 = str - 16;
        *dst2 = dst;
        result = &off_140113AE0;
        v_20 = result;
        v5 = &off_14012D060;
        v7 = &off_140113B20;
        sub_1400F6DC0(v5, 1, dst2, v7);
    }
    return result;
}