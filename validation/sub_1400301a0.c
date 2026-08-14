__int64 sub_14002CC90();
__int64 sub_140030224();
extern __int64 off_140121A14;

__int64 __fastcall sub_1400301A0(__int64 a1, __int64 a2, __int64 *a3, __int64 a4) {
    int arg_18;
    int arg_28;
    int arg_38;
    char *str;
    __int64 v4;
    __int64 v5;
    __int64 v1;

    v4 = str + 24;
    sub_14002CC90(v4, a1, a2);
    a2 = arg_18;
    v5 = arg_28;
    v1 = arg_38;
    a3 = &off_140121A14;
    a4 = *(a3 + a2*4);
    a4 += (__int64)a3;
    JUMPOUT(a4);
    v5 += 4;
    return sub_140030224();
}