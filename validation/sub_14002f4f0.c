__int64 sub_140028050();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140018400;
extern __int64 off_140113C48;

__int64 __fastcall sub_14002F4F0(int *a1, __int64 a2) {
    int arg_10;
    int arg_4;
    int arg_8;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    __int64 str;
    char *dst;
    __int64 v2;
    __int64 v5;
    __int64 v6;
    __int64 v7;
    __int64 v8;
    __int64 *src;
    __int64 *src2;
    __int64 v3;
    int v1;

    arg_8 = -2;
    *dst = 0;
    arg_4 = 0;
    v_20 = a2;
    v2 = dst - 32;
    v_30 = v2;
    v5 = &off_140018400;
    v_28 = v5;
    v6 = &off_140113C48;
    v_60 = v6;
    v_58 = 2;
    v_40 = 0;
    v7 = dst - 48;
    v_50 = v7;
    v_48 = 1;
    a2 = dst - 96;
    sub_140028050(dst, a2);
    a1 = (int *)v1;
    a1 = (int *)((__int64)(__int64)a1 & 3);
    if (a1 == 1) {
        a1 = (int *)v7;
        --v7;
        v_18 = v7;
        v8 = *(a1 - 1);
        v_10 = v8;
        src = *(a1 + 7);
        str = (__int64)src;
        src = *src;
        if (src != 0) {
            ((__int64 (*)())src)(v_10);
        }
        src2 = (__int64 *)v_10;
        v7 = str;
        v3 = v_18;
        if (arg_8 != 0) {
            if (arg_10 >= 17) {
                src2 = *(src2 - 8);
            }
            off_140108030();
            off_140108038(v7, 0, src2);
        }
        off_140108030();
        off_140108038(v7, 0, v3);
    }
    return (__int64)src2;
}