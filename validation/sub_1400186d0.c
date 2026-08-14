__int64 sub_140011970();
extern __int64 off_140119AA8;
extern __int64 off_140117680;

__int64 __fastcall sub_1400186D0(size_t *a1, __int64 a2) {
    int v_20;
    int v_28;
    char *dst;
    __int64 *src;
    __int64 v1;
    __int64 v6;
    __int64 v5;
    __int64 v3;
    __int64 v2;

    a1 = *a1;
    src = 17;
    v1 = &off_140119AA8;
    v6 = (__int64)a1;
    do {
        v5 = (__int64)src;
        src = (__int64 *)a1;
        src = (__int64 *)((__int64)(__int64)src & 15);
        v6 >>= 4;
        src = *(src + v1);
        *(dst + v5 - 18) = src;
        src = v5 - 1;
        a1 = (size_t *)v6;
    } while ((a1 > 15));
    v5 -= 2;
    v3 = v5 + dst;
    v3 -= 16;
    a1 = 17;
    a1 = (size_t *)((__int64)a1 - (__int64)src);
    v_28 = (int)a1;
    v_20 = v3;
    v2 = &off_140117680;
    return sub_140011970(a2, 1, v2, 2);
}