__int64 sub_14002CC90();
__int64 sub_140031C1B();
extern __int64 off_140121A50;

__int64 __fastcall sub_140031B30(__int64 *a1, __int64 a2, __int64 a3) {
    int arg_128;
    int arg_130;
    int arg_140;
    int arg_8;
    int arg_b0;
    int arg_c0;
    int arg_d0;
    int *v_0;
    char *str;
    __int64 v7;
    __int64 v6;
    __int64 v9;
    __int64 v8;
    __int64 *src;
    int v1;
    __int64 v2;
    __int64 v3;
    __int64 v5;

    arg_140 = -2;
    arg_130 = a3;
    v7 = a2;
    v6 = (__int64)a1;
    v9 = arg_8;
    v8 = a1[2];
    a1 = (v8 == 0) ? 1 : 0;
    src = v9 + v8;
    --src;
    a2 = (src == 0) ? 1 : 0;
    a2 |= (__int64)a1;
    if ((a2 == 0)) {
        v1 = *src;
        a1 = (v1 != 47) ? 1 : 0;
        v1 = (v1 != 92) ? 1 : 0;
        v1 &= (__int64)a1;
        arg_128 = v1;
    } else {
        arg_128 = 0;
    }
    a1 = str + 176;
    sub_14002CC90(a1, v9, v8);
    v2 = arg_b0;
    v1 = v2;
    v3 = arg_c0;
    v5 = arg_d0;
    a1 = &off_140121A50;
    v2 = v_0[(__int64)src];
    v2 += (__int64)a1;
    a2 = v8;
    a1 = (__int64 *)v9;
    JUMPOUT(v2);
    a1 = v3 + 4;
    return sub_140031C1B();
}