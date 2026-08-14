// inferred from 3 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

// inferred from 7 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_1400F7E60();
__int64 sub_1400584D0();
__int64 sub_1400F2C50();
__int64 sub_1400F27F0();
__int64 sub_1400F3869();
__int64 sub_1400F83D0();
__int64 sub_1400F3326();
__int64 sub_1400F3360();
__int64 sub_1400579C8();
extern __int64 off_140116610;

__int64 __fastcall sub_1400575F0(__int64 *a1, int *a2, int a3, __int64 *a4) {
    __int64 rsp;
    int arg_18;
    int arg_20;
    int v_20;
    int v_28;
    int v_38;
    int v_40;
    int v_48;
    int v_88;
    int v_90;
    __int64 *dst;
    __int64 v9;
    __int64 v4;
    struct Struct_2_t *ptr;
    __int64 *dst2;
    __m128i xmm0;
    struct Struct_1_t *result;
    __int64 v10;
    __int64 v7;
    __int64 v5;
    __int64 v11;
    __int64 v6;

    dst = a4;
    v9 = a3;
    v4 = (__int64)a2;
    ptr = (struct Struct_2_t *)a1;
    dst2 = (__int64 *)arg_18;
    a2 = (int *)arg_20;
    a1 = (__int64 *)a2;
    a1 = (__int64 *)((__int64)(__int64)a1 & v4);
    xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)a1));
    result = _mm_movemask_epi8(xmm0);
    if (result == 0) {
        a3 = 16;
        a1 += a3;
        a1 = (__int64 *)((__int64)(__int64)a1 & (__int64)a2);
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)a1));
        result = _mm_movemask_epi8(xmm0);
        a3 += 16;
        while (result == 0) {
        }
    }
    result = __builtin_ctz(result);
    result = (struct Struct_1_t *)((__int64)result + (__int64)a1);
    result = (struct Struct_1_t *)((__int64)(__int64)result & (__int64)a2);
    a4 = *(__int64 *)((__int64)dst2 + (__int64)result);
    if (a4 >= 0) {
        xmm0 = _mm_load_si128((__m128i *)dst2);
        result = _mm_movemask_epi8(xmm0);
        result = __builtin_ctz(result);
        a4 = *(__int64 *)((__int64)dst2 + (__int64)result);
    }
    v10 = ptr->field_30;
    v7 = ptr->field_10;
    a1 = ptr->field_28;
    a3 = (a1 == 0) ? 1 : 0;
    a4 = (__int64 *)((__int64)(__int64)a4 & 1);
    if (((__int64)a4 & a3) != 0) {
        a3 = ptr->field_8;
        a1 = ptr + 24;
        sub_1400F7E60(a1, 1, a3, v7);
        dst2 = ptr->field_18;
        v5 = ptr->field_20;
        sub_1400584D0(dst2, v5, v4);
        a3 = v4;
        a3 >>= 57;
        a2 = *(__int64 *)((__int64)dst2 + (__int64)result);
        a2 = (int *)((__int64)(__int64)a2 & 1);
        a1 = ptr->field_28;
        a1 = (__int64 *)((__int64)a1 - (__int64)a2);
        a4 = result - 16;
        a4 = (__int64 *)((__int64)(__int64)a4 & v5);
        *(__int64 *)((__int64)dst2 + (__int64)result) = a3;
        a4 = (__int64 *)((__int64)a4 + (__int64)dst2);
        v7 = ptr->field_10;
        a2 = ptr->field_30;
    } else {
        a3 = v4;
        a3 >>= 57;
        a1 = (__int64 *)((__int64)a1 - (__int64)a4);
        a4 = result - 16;
        a4 = (__int64 *)((__int64)(__int64)a4 & (__int64)a2);
        *(__int64 *)((__int64)dst2 + (__int64)result) = a3;
        a4 = (__int64 *)((__int64)a4 + (__int64)dst2);
        a2 = (int *)v10;
    }
    ptr->field_28 = a1;
    a4[2] = a3;
    ++a2;
    ptr->field_30 = a2;
    result = (struct Struct_1_t *)((__int64)(__int64)result << 3);
    dst2 = (__int64 *)((__int64)dst2 - (__int64)result);
    *(dst2 - 8) = v10;
    dst2 = ptr->field_0;
    if (v7 == dst2) {
        a1 = (__int64 *)((__int64)a1 + (__int64)a2);
        dst2 = 0x63E7063E7063E7;
        if (a1 < dst2) dst2 = a1;
        result = (struct Struct_1_t *)dst2;
        result -= v7;
        if (result <= 1) {
            a3 = ptr->field_8;
        } else {
            a3 = ptr->field_8;
            if (a1 >= v7) {
                v_28 = 328;
                v_20 = 8;
                a1 = rsp + 56;
                v11 = a3;
                sub_1400F2C50(a1, v7, a3, dst2);
                if (v_38 == 1) {
                    a3 = v11;
                    dst2 = v7 + 1;
                    v_28 = 328;
                    v_20 = 8;
                    a1 = rsp + 56;
                    sub_1400F2C50(a1, v7, a3, dst2);
                    if (v_38 != 1) {
                        result = (struct Struct_1_t *)v_40;
                        ptr->field_8 = result;
                        *(__int64 *)ptr = (__int64)(dst2);
                        a1 = rsp + 232;
                        sub_1400F27F0(a1, v9, 144);
                        a1 = rsp + 56;
                        sub_1400F27F0(a1, dst, 176);
                        dst = ptr->field_8;
                        v9 = v7 * 328;
                        a1 = dst + v9;
                        a2 = rsp + 56;
                        sub_1400F27F0(a1, a2, 320);
                        *(dst + v9 + 320) = v4;
                        a2 = v7 + 1;
                        ptr->field_10 = a2;
                        if (v10 > v7) {
                            a3 = &off_140116610;
                            sub_1400F3869(v10, a2, a3, a4);
                        } else {
                            result = v10 * 328;
                            dst = (__int64 *)((__int64)dst + (__int64)result);
                            result = (struct Struct_1_t *)dst;
                            return (__int64)result;
                        }
                    }
                } else {
                    result = (struct Struct_1_t *)v_40;
                    ptr->field_8 = result;
                    *(__int64 *)ptr = (__int64)(dst2);
                    a1 = rsp + 232;
                    sub_1400F27F0(a1, v9, 144, a4);
                    a1 = rsp + 56;
                    sub_1400F27F0(a1, dst, 176);
                    if (v7 == dst2) {
                        sub_1400F83D0(ptr);
                    }
                    return (__int64)a1;
                }
                a1 = (__int64 *)v_40;
                a2 = (int *)v_48;
                sub_1400F3326(a1, a2);
                if (a4 >= a3) JUMPOUT(0x14005817d);
                dst = a4;
                v_88 = (int)a1;
                a1 = a4 + (__int64)(__int64)a4*8;
                a1 = (__int64 *)((__int64)(__int64)a1 << 4);
                result = (__int64)a2 + (__int64)a1;
                v_90 = (int)a2;
                a1 = *(__int64 *)((__int64)a2 + (__int64)a1 + 24);
                if (a1 != a2) {
                    v10 = 0x8000000000000000;
                    v10 ^= (__int64)a1;
                    v4 = 1;
                    if (a1 >= 0) v10 = v4;
                    if (v10 == 0) JUMPOUT(0x140057ab3);
                    if (v10 == 1) {
                        v10 = result->field_28;
                        if (v10 >= 0) JUMPOUT(0x1400581f2);
                        sub_1400F3360(a1, 0x8000000000000003);
                    }
                }
                v10 = result->field_8;
                v9 = result->field_10;
                result = (v9 != 0) ? 1 : 0;
                if (v9 == 0) JUMPOUT(0x140057a54);
                v6 = (__int64)dst;
                result = 1;
                a3 = 0;
                v5 = 1;
                a1 = 0;
                v6 = 0;
                a4 = 0;
                a2 = 0;
                return sub_1400579C8();
            }
        }
        return (__int64)a2;
    }
    return (__int64)result;
}