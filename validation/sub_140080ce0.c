// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    char _pad_start[2];
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

// inferred from 3 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr2`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140081A38();
__int64 sub_140081975();
__int64 sub_140081E9E();
__int64 sub_140081B1A();
__int64 sub_140083930();
__int64 sub_14008237A();
extern __int64 off_140123424;
extern __int64 off_14012323C;
extern __int64 off_140123158;
extern __int64 off_140123180;

__int64 __fastcall sub_140080CE0(size_t *a1,struct Struct_1_t *a2,struct Struct_2_t *a3) {
    __int64 rsp;
    int arg_2;
    int arg_60;
    int arg_68;
    __int64 v_20;
    __int64 v_28;
    int v_30;
    __int64 v_4e;
    int v_4f;
    int v_50;
    int v_54;
    int v_60;
    int v_64;
    int v_70;
    int v_74;
    int v_80;
    int v_84;
    int v_8c;
    int v_94;
    int v_a0;
    int v_b0;
    int v_c0;
    int v_d0;
    int i;
    int v_ec;
    int v_f0;
    __int64 v_f1;
    __int64 v_f2;
    __int64 *i2;
    __int64 v3;
    struct Struct_4_t *ptr2;
    int v9;
    int v11;
    __int64 *result;
    __int64 *src;
    struct Struct_3_t *ptr;
    __int64 v7;
    __int64 v10;
    __int64 v8;
    int v12;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    if ((a3->field_2 & 1) == 0) {
        *a1 = 5;
    } else {
        i2 = ((__int64 *)a2)[2];
        if (i2 >= a2->field_8) {
            *a1 = 2;
            *(a1 + 2) = 0;
            a1[5] = 5;
        } else {
            v3 = a3->field_3;
            ptr2 = (struct Struct_4_t *)v3;
            ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 >> 8);
            v9 = v3;
            v9 >>= 24;
            v11 = v3;
            v11 >>= 16;
            result = a2->field_0;
            result = *(__int64 *)((__int64)result + (__int64)i2);
            ++i2;
            ((__int64 *)a2)[2] = (__int64)(i2);
            v_a0 = 4;
            v_b0 = 4;
            v_c0 = 4;
            v_d0 = 4;
            i = 0;
            i2 = ((v3 & 32) == 0) ? 1 : 0;
            if (v11 <= 2) {
                src = (__int64 *)v11;
                src = (__int64 *)((__int64)(__int64)src & 7);
                ptr = 1;
                v7 = (__int64)a1;
                a1 = (size_t *)src;
                ptr = (struct Struct_3_t *)((__int64)(__int64)ptr >> (__int64)a1);
                a1 = (size_t *)v11;
                a1 = (size_t *)((__int64)(__int64)a1 << 4);
                v10 = 0x9E009D009D;
                v10 >>= (__int64)a1;
                a1 = (size_t *)v7;
                v_ec = v11;
                v_4f = v11;
            } else {
                v_4f = 3;
                v10 = 157;
                ptr = 0;
                v_ec = 0;
            }
            v7 = (__int64)result;
            i2 = (__int64 *)((__int64)(__int64)i2 ^ 5);
            v_4e = (__int64)i2;
            v8 = v3;
            v8 &= 32;
            src = (v8 == 0) ? 1 : 0;
            v12 = v8;
            v12 >>= 5;
            ptr2 = (struct Struct_4_t *)((__int64)(__int64)ptr2 & 15);
            i2 = (__int64 *)v12;
            i2 = (__int64 *)((__int64)(__int64)i2 << 4);
            i2 = (__int64 *)((__int64)(__int64)i2 | (__int64)ptr2);
            src = (__int64 *)((__int64)(__int64)src ^ 5);
            i2 += 16;
            v_f1 = (__int64)src;
            v_f2 = (__int64)i2;
            v_f0 = 0;
            if (v9 == 1) {
                if (result >= 112) JUMPOUT(0x140081928);
                ptr2 = v7 - 40;
                if (ptr2 > 47) {
                    if (v7 == 16) JUMPOUT(0x140081a30);
                    if (v7 != 17) JUMPOUT(0x1400818dd);
                    v3 = (__int64)a1;
                    v_20 = 1;
                    return sub_140081A38();
                } else {
                    i2 = &off_140123424;
                    src = *(i2 + (__int64)(__int64)ptr2*4);
                    src = (__int64 *)((__int64)src + (__int64)i2);
                    JUMPOUT(src);
                    v3 = (__int64)a1;
                    v_20 = 0;
                    return sub_140081975();
                }
            } else {
                v12 = v9;
                if (v9 == 2) {
                    v10 = ((v3 & 16) == 0) ? 1 : 0;
                    v8 = v7 - 242;
                    if (v8 > 5) {
                        if (result < 144) {
                            if (v7 > 121) JUMPOUT(0x1400822e6);
                            i2 = (__int64 *)v7;
                            src = &off_14012323C;
                            i2 = *(src + (__int64)(__int64)i2*4);
                            i2 = (__int64 *)((__int64)i2 + (__int64)src);
                            JUMPOUT(i2);
                            result = rsp + 240;
                            v_28 = (__int64)result;
                            result = (__int64 *)v_4e;
                            v_20 = (__int64)result;
                            v_30 = 188;
                            return sub_140081E9E();
                        }
                    } else {
                        v10 ^= 3;
                        i2 = &off_140123158;
                        src = *(i2 + v8*4);
                        src = (__int64 *)((__int64)src + (__int64)i2);
                        JUMPOUT(src);
                        v12 = 99;
                        if (ptr != 0) {
                            return sub_140081B1A();
                        }
                    }
                    v7 += 0xFFFFFF70;
                    if (v7 > 46) JUMPOUT(0x140081eb0);
                    i2 = &off_140123180;
                    src = *(i2 + v7*4);
                    src = (__int64 *)((__int64)src + (__int64)i2);
                    JUMPOUT(src);
                    result = rsp + 240;
                    v_28 = (__int64)result;
                    result = (__int64 *)v_4e;
                    v_20 = (__int64)result;
                    v_30 = 203;
                    return sub_140081E9E();
                } else {
                    if (v12 != 3) JUMPOUT(0x140082375);
                    if (v7 <= 57) {
                        i2 = (__int64 *)v7;
                        switch ((__int64)i2) {
                            case 0:
                                ptr2 = (struct Struct_4_t *)a1;
                                v_20 = 0;
                                result = rsp + 160;
                                ptr = (struct Struct_3_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x140081afe);
                                a2 = ptr->field_10;
                                result = (__int64 *)ptr2;
                                if (a2 >= ptr->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                v3 &= 16;
                                a1 = 216;
                                a1 -= 0;
                                a2 = (struct Struct_1_t *)i;
                                v_94 = (int)a2;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = (int)a1;
                                return arg_2;
                            case 1:
                                v3 = (__int64)a1;
                                v_20 = 0;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 218;
                                return arg_2;
                            case 2:
                                v3 = (__int64)a1;
                                v_20 = 0;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 233;
                                return arg_2;
                            case 3:
                                break;
                            case 4:
                                v3 = (__int64)a1;
                                v_20 = 0;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 187;
                                return arg_2;
                            case 14:
                                v3 = (__int64)a1;
                                v_20 = 0;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 232;
                                return arg_2;
                            case 15:
                                v3 = (__int64)a1;
                                v_20 = 0;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 231;
                                return arg_2;
                            case 24:
                                v3 = (__int64)a1;
                                v_20 = 0;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 213;
                                return arg_2;
                            case 25:
                                v3 = (__int64)a1;
                                v_20 = 1;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 214;
                                return arg_2;
                            case 56:
                                v3 = (__int64)a1;
                                v_20 = 0;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 211;
                                return arg_2;
                            case 57:
                                v3 = (__int64)a1;
                                v_20 = 1;
                                result = rsp + 160;
                                ptr2 = (struct Struct_4_t *)a2;
                                i2 = (__int64 *)v_4e;
                                sub_140083930(a2, a3, result, i2);
                                if (result != 6) JUMPOUT(0x1400824f0);
                                a2 = ptr2->field_10;
                                result = (__int64 *)v3;
                                if (a2 >= ptr2->field_8) JUMPOUT(0x1400818cd);
                                a1 = ptr2->field_0;
                                a1 = *(__int64 *)((__int64)a1 + (__int64)a2);
                                ++a2;
                                ptr2->field_10 = a2;
                                a2 = (struct Struct_1_t *)i;
                                if (a2 <= 3) {
                                    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 << 4);
                                    *(__int64 *)(rsp + a2 + 160) = 2;
                                    *(__int64 *)(rsp + a2 + 168) = a1;
                                    ++i;
                                }
                                a1 = (size_t *)i;
                                v_94 = (int)a1;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_a0);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_b0);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_c0);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_d0);
                                _mm_storeu_si128((__m128i *)&v_84, xmm3);
                                _mm_storeu_si128((__m128i *)&v_74, xmm2);
                                _mm_storeu_si128((__m128i *)&v_64, xmm1);
                                _mm_storeu_si128((__m128i *)&v_54, xmm0);
                                *result = 186;
                                arg_2 = 212;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_50);
                                xmm1 = _mm_loadu_si128((__m128i *)&v_60);
                                xmm2 = _mm_loadu_si128((__m128i *)&v_70);
                                xmm3 = _mm_loadu_si128((__m128i *)&v_80);
                                _mm_storeu_si128((__m128i *)(result + 36), xmm0);
                                _mm_storeu_si128((__m128i *)(result + 52), xmm1);
                                _mm_storeu_si128((__m128i *)(result + 68), xmm2);
                                _mm_storeu_si128((__m128i *)(result + 84), xmm3);
                                a1 = (size_t *)v_8c;
                                arg_60 = (int)a1;
                                a1 = (size_t *)v_94;
                                arg_68 = (int)a1;
                                return arg_68;
                        }
                    }
                    *a1 = 0x3A01;
                    return sub_14008237A();
                }
            }
        }
        return arg_68;
    }
    return (__int64)result;
}