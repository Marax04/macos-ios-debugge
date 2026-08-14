__int64 sub_14002CC90();
__int64 sub_1400382D4();
extern __int64 off_140121B9C;

__int64 __fastcall sub_140038250(__int64 a1, __int64 a2, __int64 *a3, __int64 a4) {
    int arg_8;
    int v_18;
    int str;
    char *str2;
    __int64 v4;
    __int64 v5;
    __int64 v1;

    v4 = str2 - 24;
    sub_14002CC90(v4, a1, a2);
    a2 = v_18;
    v5 = str;
    v1 = arg_8;
    a3 = &off_140121B9C;
    a4 = *(a3 + a2*4);
    a4 += (__int64)a3;
    JUMPOUT(a4);
    v5 += 4;
    return sub_1400382D4();
}