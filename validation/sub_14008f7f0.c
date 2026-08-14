__int64 sub_140017F40();
__int64 sub_140011970();
extern __int64 off_140119AA8;
extern __int64 off_14010B3F0;
extern __int64 off_140117680;

__int64 __fastcall sub_14008F7F0(size_t *a1, __int64 *a2) {
    __int64 rsp;
    int v_20;
    int v_28;
    __int64 v1;
    __int64 *src;
    int v7;
    __int64 v6;
    __int64 v3;
    __int64 v4;
    __int64 v2;

    v1 = a2[2];
    if ((v1 & 0x2000000) != 0) {
        a1 = *a1;
        src = 9;
        v1 = &off_140119AA8;
        v7 = (int)a1;
        do {
            v6 = (__int64)src;
            v7 >>= 4;
            src = (__int64 *)a1;
            src = (__int64 *)((__int64)(__int64)src & 15);
            src = *(src + v1);
            *(__int64 *)(rsp + v6 + 46) = src;
            src = v6 - 1;
            a1 = (size_t *)v7;
        } while ((a1 > 15));
    } else {
        if ((v1 & 0x4000000) != 0) {
            a1 = *a1;
            src = 9;
            v3 = &off_14010B3F0;
            v7 = (int)a1;
            do {
                v6 = (__int64)src;
                v7 >>= 4;
                src = (__int64 *)a1;
                src = (__int64 *)((__int64)(__int64)src & 15);
                src = *(src + v3);
                *(__int64 *)(rsp + v6 + 46) = src;
                src = v6 - 1;
                a1 = (size_t *)v7;
            } while ((a1 > 15));
        } else {
            return sub_140017F40();
        }
    }
    v6 -= 2;
    v4 = rsp + v6;
    v4 += 48;
    a1 = 9;
    a1 = (size_t *)((__int64)a1 - (__int64)src);
    v_28 = (int)a1;
    v_20 = v4;
    v2 = &off_140117680;
    return sub_140011970(a2, 1, v2, 2);
}