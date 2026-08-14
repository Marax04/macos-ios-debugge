__int64 sub_140011970();
extern __int64 off_140119AA8;
extern __int64 off_140117680;

__int64 __fastcall sub_14008D420(size_t *a1, __int64 a2) {
    __int64 rsp;
    int v_20;
    int v_28;
    __int64 *src;
    __int64 v8;
    __int64 *src2;
    __int64 v3;
    __int64 v7;
    __int64 v6;
    __int64 v4;
    __int64 v2;

    src = *a1;
    v8 = *src;
    src2 = 17;
    v3 = &off_140119AA8;
    v7 = v8;
    do {
        v6 = (__int64)src2;
        src2 = (__int64 *)a1;
        src2 = (__int64 *)((__int64)(__int64)src2 & 15);
        v7 >>= 4;
        src2 = *(src2 + v3);
        *(__int64 *)(rsp + v6 + 54) = src2;
        src2 = v6 - 1;
        v8 = v7;
    } while ((v8 > 15));
    v6 -= 2;
    v4 = rsp + v6;
    v4 += 56;
    a1 = 17;
    v8 -= (__int64)src2;
    v_28 = v8;
    v_20 = v4;
    v2 = &off_140117680;
    return sub_140011970(a2, 1, v2, 2);
}