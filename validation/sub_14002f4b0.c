__int64 sub_14002F4D0();
__int64 sub_14002F4F0();
__int64 sub_140028050();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140018400;
extern __int64 off_140113C48;

__int64 __fastcall sub_14002F4B0(int *a1, __int64 a2) {
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
    __int64 v5;
    __int64 v6;
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 *src2;
    __int64 *src3;
    __int64 v3;
    __int64 *src;

    sub_14002F4D0(a2, a1);
    sub_14002F4F0();
    a1 = 7;
    /* int $41 */;
    arg_8 = -2;
    *dst = 0;
    arg_4 = 0;
    v_20 = a2;
    v5 = dst - 32;
    v_30 = v5;
    v6 = &off_140018400;
    v_28 = v6;
    v7 = &off_140113C48;
    v_60 = v7;
    v_58 = 2;
    v_40 = 0;
    v8 = dst - 48;
    v_50 = v8;
    v_48 = 1;
    a2 = dst - 96;
    sub_140028050(dst, a2);
    a1 = (int *)src;
    a1 = (int *)((__int64)(__int64)a1 & 3);
    if (a1 == 1) {
        a1 = (int *)v8;
        --v8;
        v_18 = v8;
        v9 = *(a1 - 1);
        v_10 = v9;
        src2 = *(a1 + 7);
        str = (__int64)src2;
        src2 = *src2;
        if (src2 != 0) {
            a1 = (int *)v_10;
            ((__int64 (*)())src2)(a1);
        }
        src3 = (__int64 *)v_10;
        v8 = str;
        v3 = v_18;
        if (arg_8 != 0) {
            if (arg_10 >= 17) {
                src3 = *(src3 - 8);
            }
            off_140108030();
            off_140108038(v8, 0, src3);
        }
        off_140108030();
        off_140108038(v8, 0, v3);
    }
    return (__int64)src3;
}