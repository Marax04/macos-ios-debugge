// [crypto] AES round constants
// inferred from 2 accesses on `a3`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[2];
    __int64 field_2; // offset 2
    char _pad_2[86];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
};

__int64 sub_1400831E0();
extern __int64 off_140123C40;
extern __int64 off_140123DCC;
extern __int64 off_140123DAC;
extern __int64 off_140123D74;
extern __int64 off_140123D54;
extern __int64 off_140123D1C;

__int64 __fastcall sub_1400858A0(size_t *a1, size_t *a2,struct Struct_1_t *a3) {
    __int64 rsp;
    __int64 arg_1;
    int arg_2;
    int arg_4;
    int v_20;
    __int64 v_28;
    int v_2c;
    __int64 v_30;
    __int64 v_38;
    int v_3c;
    __int64 v_3e;
    int v_48;
    int v_4c;
    int v_50;
    int v_58;
    int v_59;
    int v_5a;
    int v_5b;
    int v_5c;
    int v_64;
    int v_6c;
    int v_f0;
    __int64 *i;
    __int64 *result;
    __int64 v2;
    struct Struct_2_t *ptr;
    __int64 v4;
    __int64 *src;
    __int64 *src2;
    __m128i xmm3;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;

    i = ((__int64 *)a3)[2];
    if (i >= a3->field_8) {
        *a1 = 2;
    } else {
        result = a3->field_0;
        result = *(__int64 *)((__int64)result + (__int64)i);
        if (result < 192) {
            result = (__int64 *)((__int64)(__int64)result >> 3);
            result = (__int64 *)((__int64)(__int64)result & 7);
            a2 += 0xFFFFFF28;
            i = &off_140123C40;
            a2 = *(i + (__int64)(__int64)a2*4);
            a2 = (size_t *)((__int64)a2 + (__int64)i);
            JUMPOUT(a2);
            v2 = (__int64)a1;
            result = (__int64 *)((__int64)(__int64)result << 3);
            ptr = 0x1916100D1D1C130A;
            a1 = (size_t *)result;
            ptr = (struct Struct_2_t *)((__int64)(__int64)ptr >> (__int64)a1);
            i = 2;
            v4 = 3;
        } else {
            ++i;
            ((__int64 *)a3)[2] = (__int64)(i);
            src = result;
            src = (__int64 *)((__int64)(__int64)src >> 3);
            src = (__int64 *)((__int64)(__int64)src & 7);
            result = (__int64 *)((__int64)(__int64)result & 7);
            a2 += 0xFFFFFF28;
            switch ((__int64)a2) {
                case 0:
                    a3 = 2;
                    a2 = 1;
                    i = &off_140123DCC;
                    src = *(i + (__int64)(__int64)src*4);
                    src = (__int64 *)((__int64)src + (__int64)i);
                    JUMPOUT(src);
                    ptr = 10;
                    return (__int64)ptr;
                case 1:
                    a3 = 1;
                    a2 = 3;
                    i = src;
                    src2 = &off_140123DAC;
                    i = *(src2 + (__int64)(__int64)i*4);
                    i = (__int64 *)((__int64)i + (__int64)src2);
                    JUMPOUT(i);
                    v4 = (__int64)result;
                    ptr = (struct Struct_2_t *)src;
                    result = 3;
                    return (__int64)result;
                case 3:
                    a3 = 2;
                    a2 = 1;
                    v4 = 3;
                    i = &off_140123D74;
                    src = *(i + (__int64)(__int64)src*4);
                    src = (__int64 *)((__int64)src + (__int64)i);
                    JUMPOUT(src);
                    ptr = 90;
                    return (__int64)ptr;
                case 4:
                    a2 = 1;
                    a3 = (struct Struct_1_t *)src;
                    src = &off_140123D54;
                    a3 = *(src + (__int64)(__int64)a3*4);
                    a3 = (struct Struct_1_t *)((__int64)a3 + (__int64)src);
                    JUMPOUT(a3);
                    ptr = 10;
                    return (__int64)ptr;
                case 6:
                    a2 = 1;
                    ptr = 23;
                    a3 = (struct Struct_1_t *)src;
                    src = &off_140123D1C;
                    a3 = *(src + (__int64)(__int64)a3*4);
                    a3 = (struct Struct_1_t *)((__int64)a3 + (__int64)src);
                    JUMPOUT(a3);
                    ptr = 11;
                    return (__int64)ptr;
                case 13:
                    return (__int64)ptr;
                case 25:
                    return (__int64)ptr;
                case 31:
                    v2 = (__int64)a1;
                    result = 4;
                    a2 = 5;
                    i = 3;
                    ptr = (struct Struct_2_t *)result;
                    v4 = (__int64)a2;
                    break;
                case 33:
                    ptr = 5;
                    break;
                case 34:
                    ptr = 74;
                    v4 = (__int64)result;
                    return v4;
                case 38:
                    return v4;
                case 40:
                    v_3e = (__int64)result;
                    ptr = 74;
                    return (__int64)ptr;
                case 44:
                    ptr = 29;
                    v4 = (__int64)result;
                    result = 0;
                    a3 = 1;
                    return (__int64)a3;
                case 45:
                    return (__int64)a3;
                case 49:
                    return (__int64)a3;
                case 53:
                    v4 = (__int64)result;
                    return v4;
                case 57:
                    ptr = 0x2B2A33352C323136;
                    a2 = a1;
                    a1 = (size_t *)result;
                    ptr = (struct Struct_2_t *)((__int64)(__int64)ptr >> (__int64)a1);
                    a1 = a2;
                    result = 0x303030303030303;
                    v_28 = (__int64)result;
                    v_30 = 0x3030303;
                    v_38 = (__int64)result;
                    v_3e = (__int64)result;
                    v4 = 3;
                    result = 3;
                    a2 = 3;
                    a3 = 3;
                    *a1 = a3;
                    arg_1 = v4;
                    arg_2 = 771;
                    a3 = (struct Struct_1_t *)v_28;
                    arg_4 = (int)a3;
                    a3 = (struct Struct_1_t *)v_30;
                    a1[1] = a3;
                    a1[2] = a2;
                    a1[2] = result;
                    result = (__int64 *)v_38;
                    a2 = (size_t *)v_3e;
                    a1[2] = result;
                    a1[3] = a2;
                    a1[4] = ptr;
                    a1[5] = 4;
                    a1[7] = 4;
                    a1[9] = 4;
                    a1[11] = 4;
                    a2 = 104;
                    result = 0;
                    *(__int64 *)((__int64)a1 + (__int64)a2) = result;
                    return (__int64)result;
                case 170:
                    xmm3 = _mm_loadu_si128((__m128i *)&v_f0);
                    _mm_storeu_si128((__m128i *)&v_5c, xmm3);
                    _mm_storeu_si128((__m128i *)&v_4c, xmm2);
                    _mm_storeu_si128((__m128i *)&v_3c, xmm1);
                    _mm_storeu_si128((__m128i *)&v_2c, xmm0);
                    *(__int64 *)ptr = (__int64)(186);
                    ptr->field_2 = 54;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                    xmm1 = _mm_loadu_si128((__m128i *)&v_38);
                    xmm2 = _mm_loadu_si128((__m128i *)&v_48);
                    xmm3 = _mm_loadu_si128((__m128i *)&v_58);
                    _mm_storeu_si128((__m128i *)(ptr + 36), xmm0);
                    _mm_storeu_si128((__m128i *)(ptr + 52), xmm1);
                    _mm_storeu_si128((__m128i *)(ptr + 68), xmm2);
                    _mm_storeu_si128((__m128i *)(ptr + 84), xmm3);
                    result = (__int64 *)v_64;
                    ptr->field_60 = result;
                    result = (__int64 *)v_6c;
                    ptr->field_68 = result;
                    return (__int64)result;
                default:
                    a1 = (size_t *)v_64;
                    v_50 = (int)a1;
                    a1 = (size_t *)v_5c;
                    v_48 = (int)a1;
                    a1 = (size_t *)v2;
                    if (result != 1) {
                        src2 = 5;
                        *a1 = src2;
                        arg_1 = (__int64)result;
                        arg_2 = (int)a2;
                        result = 5;
                        a2 = 40;
                    } else {
                        result = (__int64 *)v_50;
                        v_30 = (__int64)result;
                        result = (__int64 *)v_48;
                        v_28 = (__int64)result;
                        a2 = 3;
                        a3 = 0;
                        return (__int64)a3;
                    }
                    return (__int64)a3;
            }
        }
        v_20 = 0;
        a1 = rsp + 88;
        sub_1400831E0(a1, a3, src, i);
        result = (__int64 *)v_58;
        if (result != 4) {
            return (__int64)result;
        } else {
            src2 = (__int64 *)v_59;
            result = (__int64 *)v_5a;
            a2 = (size_t *)v_5b;
            a1 = (size_t *)v2;
        }
        return (__int64)a1;
    }
    return (__int64)result;
}