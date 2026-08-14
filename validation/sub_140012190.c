__int64 sub_1400123C1();
__int64 sub_1400126B0();
__int64 sub_1400123B8();
extern __int64 off_140119AA8;

__int64 __fastcall sub_140012190(int *a1, size_t a2, size_t a3) {
    int v_1;
    int v_2;
    __int64 v_3;
    __int64 str;
    __int64 v_5;
    __int64 v_6;
    __int64 v_7;
    int v_8;
    int v_a;
    char *dst;
    __int64 *src;
    __int64 result;
    __int64 v4;
    __int64 v6;
    __int64 *src2;
    __int64 v2;
    __int64 v7;

    src = (__int64 *)a2;
    if (a2 <= 39) {
        result = (__int64)src;
        switch (result) {
            case 0:
                *a1 = 0x305C;
                return sub_1400123C1();
            case 9:
                *a1 = 0x745C;
                return sub_1400123C1();
            case 10:
                *a1 = 0x6E5C;
                return sub_1400123C1();
            case 13:
                *a1 = 0x725C;
                return sub_1400123C1();
            case 34:
                a3 &= 0xFFFFFF;
                if (a3 >= 0x10000) JUMPOUT(0x1400123bc);
                return a3;
            default:
                result = (src >= 768) ? 1 : 0;
                if ((a3 & result) != 0) {
                    v4 = (__int64)a1;
                    sub_1400126B0(src);
                    a1 = (int *)v4;
                    if (result != 0) {
                        result = (__int64)src;
                        result |= 1;
                        a2 = 31 - __builtin_clz(result);
                        a2 ^= 28;
                        a2 >>= 2;
                        v6 = a2 - 2;
                        v_8 = 0;
                        v_a = 0;
                        src2 = src;
                        src2 = (__int64 *)((__int64)(__int64)src2 >> 20);
                        v2 = &off_140119AA8;
                        src2 = *(src2 + v2);
                        v_7 = (__int64)src2;
                        src2 = src;
                        src2 = (__int64 *)((__int64)(__int64)src2 >> 16);
                        src2 = (__int64 *)((__int64)(__int64)src2 & 15);
                        src2 = *(src2 + v2);
                        v_6 = (__int64)src2;
                        src2 = src;
                        src2 = (__int64 *)((__int64)(__int64)src2 >> 12);
                        src2 = (__int64 *)((__int64)(__int64)src2 & 15);
                        src2 = *(src2 + v2);
                        v_5 = (__int64)src2;
                        src2 = src;
                        src2 = (__int64 *)((__int64)(__int64)src2 >> 8);
                        src2 = (__int64 *)((__int64)(__int64)src2 & 15);
                        src2 = *(src2 + v2);
                        str = (__int64)src2;
                        src2 = src;
                        src2 = (__int64 *)((__int64)(__int64)src2 >> 4);
                        src2 = (__int64 *)((__int64)(__int64)src2 & 15);
                        src2 = *(src2 + v2);
                        v_3 = (__int64)src2;
                        src = (__int64 *)((__int64)(__int64)src & 15);
                        a3 = *(src + v2);
                        v_2 = a3;
                        v_1 = 125;
                        *(dst + a2 - 12) = 0x755C;
                        *(dst + a2 - 10) = 123;
                        a2 = v_2;
                        *(a1 + 8) = a2;
                        v7 = v_a;
                        *a1 = v7;
                        return sub_1400123B8();
                    }
                }
                return v7;
        }
    }
    if (src != 92) {
        return result;
    } else {
        *a1 = 0x5C5C;
        return sub_1400123C1();
    }
}