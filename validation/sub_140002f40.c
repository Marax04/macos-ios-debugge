__int64 sub_1400318D0();
__int64 sub_14000EFE0();
__int64 sub_1400F2B40();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F32C0();
__int64 sub_140011760();
__int64 sub_140034600();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1400456F0;
extern __int64 off_140109570;
extern __int64 off_140109428;
extern __int64 off_140109548;
extern __int64 off_14000E2E0;
extern __int64 off_140109730;
extern __int64 off_14008FE80;
extern __int64 off_1401175D8;
extern __int64 off_14011D9F8;
extern __int64 off_14010A9A8;
extern __int64 off_14000C620;
extern __int64 off_140109500;

__int64 __fastcall sub_140002F40(int *a1, int *str, __int64 *a3) {
    __int64 rsp;
    int arg_10;
    int arg_30;
    int arg_8;
    int v_28;
    __int64 v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    __int64 v_58;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_90;
    __int64 v_98;
    int v_a0;
    int v_b0;
    int v_c0;
    char *str2;
    char *str3;
    __int64 v4;
    __int64 *dst;
    __int64 v2;
    __int64 v5;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v8;
    __int64 i;
    __int64 result;
    __int64 v7;
    __int64 v9;

    v4 = (__int64)a3;
    dst = (__int64 *)str;
    v2 = (__int64)a1;
    a3 = (__int64 *)arg_8;
    v5 = arg_10;
    sub_1400318D0(a1, str, a3, v5);
    if (result != 0) {
        v_50 = v2;
        v_58 = (__int64)dst;
        a1 = rsp + 80;
        str2 = (char *)a1;
        a1 = &off_1400456F0;
        v_68 = (int)a1;
        a1 = &off_140109570;
        str = a1;
        v_28 = 1;
        a1 = rsp + 96;
        v_30 = (__int64)a1;
        v_38 = 1;
        v_40 = 0;
        dst = rsp + 120;
        v4 = result;
        sub_14000EFE0(dst, str);
        sub_1400F2B40(result, dst);
    } else {
        if (arg_30 == 1) {
            xmm0 = _mm_loadu_si128((__m128i *)(v4 + 49));
            xmm1 = _mm_loadu_si128((__m128i *)(v4 + 65));
            _mm_store_si128((__m128i *)&v_c0, xmm1);
            _mm_store_si128((__m128i *)&v_b0, xmm0);
            v_50 = v2;
            v_58 = (__int64)dst;
            v8 = rsp + 80;
            str2 = (char *)v8;
            i = &off_1400456F0;
            v_68 = i;
            result = &off_140109428;
            str = (int *)result;
            v_28 = 2;
            v_30 = (__int64)str2;
            v_38 = 1;
            v_40 = 0;
            a1 = rsp + 120;
            sub_14000EFE0(a1, str);
            dst = (__int64 *)v_78;
            v7 = v_80;
            v2 = v_88;
            xmm0 = _mm_loadu_si128((__m128i *)(v4 + 49));
            xmm1 = _mm_loadu_si128((__m128i *)(v4 + 65));
            _mm_store_si128((__m128i *)&v_30, xmm1);
            _mm_store_si128((__m128i *)&str, xmm0);
            a3 = rsp + 32;
            sub_1400318D0(v7, v2, a3, 32);
            if (result != 0) {
                v_50 = v7;
                v_58 = v2;
                str2 = (char *)v8;
                v_68 = i;
                a1 = &off_140109548;
                str = a1;
                v_28 = 1;
                v_30 = (__int64)str2;
                v_38 = 1;
                v_40 = 0;
                v4 = rsp + 120;
                v2 = result;
                sub_14000EFE0(v4, str);
                sub_1400F2B40(result, v4);
                if (dst != 0) {
                    dst = (__int64 *)result;
                    off_140108030();
                    off_140108038(result, 0, v7);
                    result = (__int64)dst;
                }
            } else {
                v4 = (__int64)str2;
                v_98 = (__int64)dst;
                v_a0 = v7;
                v_50 = v7;
                v_58 = v2;
                sub_14002EDF0(0, 64);
                if (result == 0) {
                    sub_1400F3326(1, 64);
                    result = a3 - 4;
                    if (result <= 10) {
                        switch (result) {
                            case 2:
                                break;
                            default:
                                if (*str == 0x656E6F6E) {
                                    *a1 = 0;
                                    return result;
                                }
                                break;
                        }
                    }
                    v_28 = (int)a3;
                    result = rsp + 32;
                    v_30 = result;
                    result = &off_14000E2E0;
                    v_38 = result;
                    result = &off_140109730;
                    v_40 = result;
                    v_48 = 2;
                    str2 = 0;
                    result = rsp + 48;
                    v_50 = result;
                    v_58 = 1;
                    result = rsp + 64;
                    dst = (__int64 *)a1;
                    sub_1400F32C0(result, str, a3, v5);
                    arg_8 = result;
                    *dst = 1;
                    return arg_8;
                } else {
                    v_78 = 64;
                    v_80 = result;
                    v_88 = 0;
                    i = 0;
                    v8 = &off_14008FE80;
                    dst = &off_1401175D8;
                    v9 = &off_14011D9F8;
                    v2 = &off_14010A9A8;
                    do {
                        result = rsp + i;
                        result += 176;
                        ++i;
                        str3 = (char *)result;
                        str2 = str3;
                        v_68 = v8;
                        str = (int *)dst;
                        v_28 = 1;
                        v_40 = v9;
                        v_48 = 1;
                        v_30 = v4;
                        v_38 = 1;
                        a1 = rsp + 120;
                        sub_140011760(a1, v2, str);
                    } while (i != 32);
                    result = v_88;
                    v_70 = result;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_78);
                    _mm_store_si128((__m128i *)&str2, xmm0);
                    result = rsp + 80;
                    v_78 = result;
                    result = &off_1400456F0;
                    v_80 = result;
                    v_88 = v4;
                    result = &off_14000C620;
                    v_90 = result;
                    result = &off_140109500;
                    str = (int *)result;
                    v_28 = 3;
                    v_40 = 0;
                    result = rsp + 120;
                    v_30 = result;
                    v_38 = 2;
                    a1 = rsp + 32;
                    sub_140034600(a1);
                    if (str2 != 0) {
                        v4 = v_68;
                        off_140108030();
                        off_140108038(result, 0, v4);
                    }
                    dst = (__int64 *)v_a0;
                    if (v_98 != 0) {
                        off_140108030();
                        off_140108038(result, 0, dst);
                    }
                    result = 0;
                }
            }
            return result;
        }
        return result;
    }
    return result;
}