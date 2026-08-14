__int64 sub_140011970();
extern __int64 off_140119AA8;
extern __int64 off_14010B3F0;
extern __int64 off_14010B327;
extern __int64 off_140117680;

__int64 __fastcall sub_140029040(size_t *a1, __int64 *a2) {
    int v_20;
    int v_28;
    int str;
    char *dst;
    __int64 result;
    __int64 *src;
    __int64 v10;
    __int64 v3;
    __int64 v7;
    __int64 v9;
    __int64 v4;
    __int64 v5;
    __int64 *src2;
    __int64 *src3;

    result = a2[2];
    if ((result & 0x2000000) != 0) {
        result = *a1;
        src = 3;
        v10 = &off_140119AA8;
        do {
            v3 = (__int64)src;
            v7 = result;
            result >>= 4;
            src = (__int64 *)v7;
            src = (__int64 *)((__int64)(__int64)src & 15);
            src = *(src + v10);
            *(dst + v3 - 4) = src;
            src = v3 - 1;
        } while (v7 > 15);
        v3 -= 2;
        v9 = v3 + dst;
        v9 -= 2;
    } else {
        if ((result & 0x4000000) != 0) {
            result = *a1;
            src = 3;
            v10 = &off_14010B3F0;
            do {
                v4 = (__int64)src;
                v7 = result;
                result >>= 4;
                src = (__int64 *)v7;
                src = (__int64 *)((__int64)(__int64)src & 15);
                src = *(src + v10);
                *(dst + v4 - 9) = src;
                src = v4 - 1;
            } while (v7 > 15);
            v4 -= 2;
            v9 = v4 + dst;
            v9 -= 7;
        } else {
            a1 = *a1;
            result = 3;
            v5 = (__int64)a1;
            if (a1 >= 10) {
                result = (__int64)a1;
                v5 = result + result*4;
                v5 = result + v5*8;
                v5 >>= 12;
                result = v5 * 100;
                src = (__int64 *)a1;
                src -= result;
                result = (__int64)src;
                src2 = &off_14010B327;
                result = *(src2 + result*2);
                str = result;
                result = 1;
            }
            src = (v5 == 0) ? 1 : 0;
            a1 = (a1 != 0) ? 1 : 0;
            if (((__int64)a1 & (__int64)src) == 0) {
                a1 = (size_t *)v5;
                src3 = &off_14010B327;
                a1 = *(src3 + (__int64)(__int64)a1*2 + 1);
                *(dst + result - 6) = a1;
                --result;
            }
            a1 = 3;
            a1 -= result;
            result += (__int64)dst;
            result -= 5;
            v_28 = (int)a1;
            v_20 = result;
            sub_140011970(a2, 1, 1, 0);
            return result;
        }
    }
    a1 = 3;
    v10 -= (__int64)src;
    v_28 = v10;
    v_20 = v9;
    v7 = &off_140117680;
    return sub_140011970(a2, 1, v7, 2);
}