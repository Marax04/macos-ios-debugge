__int64 sub_140011760();
extern __int64 off_140116220;
extern __int64 off_140053B90;
extern __int64 off_140050370;
extern __int64 off_1401175D8;

__int64 __fastcall sub_1400502A0(__int64 *a1, int a2, int *a3, __int64 a4) {
    int v_30;
    int v_40;
    __int64 v_48;
    int v_50;
    int v_58;
    char *str;
    char *str2;
    char *str3;
    __int64 result;
    __int64 v5;
    __int64 v2;
    __int64 v6;
    __int64 v3;
    __int64 v4;

    result = a2;
    v5 = *a1;
    a4 = 0x8000000000000000;
    a4 ^= v5;
    /* test v5 , v5 */;
    a2 = 1;
    if (0 /* unresolved: flags < 0 */) v5 = a4;
    if (v5 == 0) {
        v2 = a3[3];
        v6 = &off_140116220;
        a3 = 5;
        a1 = (__int64 *)result;
        JUMPOUT(v2);
    } else {
        if (v5 != 1) {
            a1 += 8;
            str = (char *)a1;
            str2 = str;
            v3 = &off_140053B90;
        } else {
            str = (char *)a1;
            str2 = str;
            v3 = &off_140050370;
        }
        v_30 = v3;
        v4 = &off_1401175D8;
        str3 = (char *)v4;
        v_40 = 1;
        v_58 = 0;
        v_48 = (__int64)str2;
        v_50 = 1;
        return sub_140011760(result, a3, str3, str3);
    }
    return result;
}