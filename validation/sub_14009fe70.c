__int64 sub_140011970();
extern __int64 off_140119AA8;
extern __int64 off_140117680;

__int64 __fastcall sub_14009FE70(int *a1, __int64 a2) {
    __int64 rsp;
    int v_20;
    int v_28;
    __int64 *src;
    __int64 *src2;
    __int64 v4;
    __int64 v5;
    __int64 v7;
    __int64 v3;
    __int64 v2;

    src = *a1;
    src = *src;
    src2 = 5;
    v4 = &off_140119AA8;
    do {
        v5 = (__int64)src2;
        v7 = (__int64)src;
        src = (__int64 *)v7;
        src = (__int64 *)((__int64)(__int64)src >> 4);
        src2 = (__int64 *)v7;
        src2 = (__int64 *)((__int64)(__int64)src2 & 15);
        src2 = *(src2 + v4);
        *(__int64 *)(rsp + v5 + 50) = src2;
        src2 = v5 - 1;
    } while (v7 > 15);
    v5 -= 2;
    v3 = rsp + v5;
    v3 += 52;
    a1 = 5;
    v4 -= (__int64)src2;
    v_28 = v4;
    v_20 = v3;
    v2 = &off_140117680;
    return sub_140011970(a2, 1, v2, 2);
}