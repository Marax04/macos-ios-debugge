__int64 sub_14002CC90();
__int64 sub_14002CBD2();
extern __int64 off_140121418;

int __fastcall sub_14002CB50(__int64 a1, __int64 a2) {
    int v_18;
    int v_28;
    int v_8;
    char *str;
    __int64 v2;
    __int64 v8;
    __int64 v9;
    __int64 v5;
    __int64 *src;
    __int64 v7;

    v2 = str - 40;
    sub_14002CC90(v2, a1, a2);
    v8 = v_18;
    v9 = v_8;
    v5 = v_28;
    src = &off_140121418;
    v7 = *(src + v5*4);
    v7 += (__int64)src;
    JUMPOUT(v7);
    v8 += 4;
    return sub_14002CBD2();
}