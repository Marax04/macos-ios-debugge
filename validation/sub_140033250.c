__int64 sub_140017F40();
__int64 sub_140011970();
extern __int64 off_14011DD78;
extern __int64 off_14011DEC8;
extern __int64 off_140119AA8;
extern __int64 off_14010B3F0;
extern __int64 off_140117680;

__int64 __fastcall sub_140033250(size_t *a1, __int64 *a2, int *a3) {
    int v_20;
    __int64 v_28;
    char *dst;
    __int64 v5;
    __int64 *src;
    __int64 *src2;
    __int64 v2;
    __int64 *src3;
    __int64 *src4;
    __int64 v8;
    __int64 v7;
    __int64 v9;
    __int64 v10;
    __int64 v4;

    v5 = (__int64)a2;
    src = &off_14011DD78;
    src = src[(__int64)a1];
    src2 = &off_14011DEC8;
    a2 = *(src2 + (__int64)(__int64)a1*4);
    a2 = (__int64 *)((__int64)a2 + (__int64)src2);
    v2 = a3[3];
    src3 = (__int64 *)v5;
    src4 = src;
    JUMPOUT(v2);
    src = a2[2];
    if (((__int64)src & 0x2000000) != 0) {
        a1 = *src3;
        a3 = 9;
        v8 = &off_140119AA8;
        src2 = (__int64 *)a1;
        do {
            v7 = (__int64)src4;
            src2 = (__int64 *)((__int64)(__int64)src2 >> 4);
            a3 = (int *)a1;
            a3 = (int *)((__int64)(__int64)a3 & 15);
            a3 = *(src4 + v8);
            *(dst + v7 - 10) = a3;
            src4 = v7 - 1;
            a1 = (size_t *)src2;
        } while ((a1 > 15));
    } else {
        if (((__int64)src & 0x4000000) != 0) {
            a1 = *src3;
            a3 = 9;
            v9 = &off_14010B3F0;
            src2 = (__int64 *)a1;
            do {
                v7 = (__int64)src4;
                src2 = (__int64 *)((__int64)(__int64)src2 >> 4);
                a3 = (int *)a1;
                a3 = (int *)((__int64)(__int64)a3 & 15);
                a3 = *(src4 + v9);
                *(dst + v7 - 10) = a3;
                src4 = v7 - 1;
                a1 = (size_t *)src2;
            } while ((a1 > 15));
        } else {
            return sub_140017F40();
        }
    }
    v7 -= 2;
    v10 = v7 + dst;
    v10 -= 8;
    a1 = 9;
    src3 = (__int64 *)((__int64)src3 - (__int64)src4);
    v_28 = (__int64)src3;
    v_20 = v10;
    v4 = &off_140117680;
    return sub_140011970(a2, 1, v4, 2);
}