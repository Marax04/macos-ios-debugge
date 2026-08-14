// inferred from 3 accesses on `result`
struct Struct_1_t {
    char _pad_start[2];
    __int64 field_2; // offset 2
    char _pad_2[86];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    char _pad_30[8];
    __int64 field_40; // offset 64
};

// inferred from 4 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    char _pad_30[8];
    __int64 field_40; // offset 64
};

// inferred from 3 accesses on `ptr4`
struct Struct_5_t {
    __int16 field_0; // offset 0
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

__int64 sub_140083930();
__int64 sub_1400831E0();
__int64 sub_1400898F0();
extern __int64 off_1401241DC;

__int64 __fastcall sub_140089B20(size_t *a1, int *a2, size_t *a3, size_t *a4) {
    __int64 rsp;
    __int64 arg_2;
    int v_150;
    int v_158;
    int v_160;
    int v_168;
    __int64 v_20;
    int v_28;
    int v_30;
    __int64 v_3c;
    __int64 v_3e;
    int v_40;
    int v_41;
    int v_43;
    int v_44;
    int v_4c;
    int v_50;
    int v_54;
    int v_60;
    int v_64;
    int v_70;
    int v_74;
    int v_7c;
    __int64 v_84;
    __int64 v_90;
    __int64 v_92;
    int v_a0;
    int v_b0;
    int v_c0;
    __int64 v_d0;
    __int64 v_f0;
    __int64 v_f8;
    __int64 v6;
    struct Struct_1_t *result;
    __int64 i;
    struct Struct_3_t *ptr2;
    struct Struct_2_t *ptr;
    struct Struct_4_t *ptr3;
    __int64 *dst;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    struct Struct_5_t *ptr4;

    v6 = (__int64)a2;
    v6 += 0xFFFFFFA0;
    if (v6 <= 158) {
        result = (struct Struct_1_t *)a4;
        i = v_168;
        ptr2 = (struct Struct_3_t *)v_160;
        ptr = (struct Struct_2_t *)v_158;
        ptr3 = (struct Struct_4_t *)v_150;
        dst = &off_1401241DC;
        switch (v6) {
            case 0:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 234;
                return v_30;
            case 1:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 235;
                return v_30;
            case 2:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 236;
                return v_30;
            case 3:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 242;
                return v_30;
            case 4:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 228;
                return v_30;
            case 5:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 229;
                return v_30;
            case 6:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 186;
                return v_30;
            case 7:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 244;
                return v_30;
            case 8:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 238;
                return v_30;
            case 9:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 239;
                return v_30;
            case 10:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 240;
                return v_30;
            case 11:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 243;
                return v_30;
            case 12:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 237;
                return v_30;
            case 13:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 241;
                return v_30;
            case 14:
                *a1 = 0xF01;
                arg_2 = (__int64)a2;
                a1[5] = 5;
                break;
            case 20:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 184;
                return v_30;
            case 21:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 226;
                return v_30;
            case 22:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 185;
                return v_30;
            case 23:
                result = 0;
                result = (ptr == 5) ? 1 : 0;
                result += 191;
                a2 = ptr3->field_40;
                v_d0 = (__int64)a2;
                xmm0 = _mm_loadu_si128((__m128i *)ptr3);
                xmm1 = _mm_loadu_si128((__m128i *)(ptr3 + 16));
                xmm2 = _mm_loadu_si128((__m128i *)(ptr3 + 32));
                xmm3 = _mm_loadu_si128((__m128i *)(ptr3 + 48));
                _mm_store_si128((__m128i *)&v_c0, xmm3);
                _mm_store_si128((__m128i *)&v_b0, xmm2);
                _mm_store_si128((__m128i *)&v_a0, xmm1);
                _mm_store_si128((__m128i *)&v_90, xmm0);
                *(__int64 *)ptr3 = (__int64)(4);
                ptr3->field_10 = 4;
                ptr3->field_20 = 4;
                ptr3->field_30 = 4;
                ptr3->field_40 = 0;
                a2 = (int *)v_d0;
                v_84 = (__int64)a2;
                xmm0 = _mm_load_si128((__m128i *)&v_90);
                xmm1 = _mm_load_si128((__m128i *)&v_a0);
                xmm2 = _mm_load_si128((__m128i *)&v_b0);
                xmm3 = _mm_load_si128((__m128i *)&v_c0);
                _mm_storeu_si128((__m128i *)&v_74, xmm3);
                _mm_storeu_si128((__m128i *)&v_64, xmm2);
                _mm_storeu_si128((__m128i *)&v_54, xmm1);
                _mm_storeu_si128((__m128i *)&v_44, xmm0);
                *a1 = 186;
                arg_2 = (__int64)result;
                xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                xmm1 = _mm_loadu_si128((__m128i *)&v_50);
                xmm2 = _mm_loadu_si128((__m128i *)&v_60);
                xmm3 = _mm_loadu_si128((__m128i *)&v_70);
                _mm_storeu_si128((__m128i *)(a1 + 36), xmm0);
                _mm_storeu_si128((__m128i *)(a1 + 52), xmm1);
                _mm_storeu_si128((__m128i *)(a1 + 68), xmm2);
                _mm_storeu_si128((__m128i *)(a1 + 84), xmm3);
                result = (struct Struct_1_t *)v_7c;
                a1[12] = result;
                result = (struct Struct_1_t *)v_84;
                a1[13] = result;
                break;
            case 30:
                dst = (__int64 *)a1;
                if (ptr2 != 2) JUMPOUT(0x14008a466);
                v_20 = 0;
                ptr2 = (struct Struct_3_t *)ptr3;
                sub_140083930(a3, result, ptr3, ptr);
                if (result != 6) {
                    return (__int64)ptr2;
                } else {
                    result = ptr2->field_40;
                    v_d0 = (__int64)result;
                    xmm0 = _mm_loadu_si128((__m128i *)ptr2);
                    xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + 16));
                    xmm2 = _mm_loadu_si128((__m128i *)(ptr2 + 32));
                    xmm3 = _mm_loadu_si128((__m128i *)(ptr2 + 48));
                    _mm_store_si128((__m128i *)&v_c0, xmm3);
                    _mm_store_si128((__m128i *)&v_b0, xmm2);
                    _mm_store_si128((__m128i *)&v_a0, xmm1);
                    _mm_store_si128((__m128i *)&v_90, xmm0);
                    *(__int64 *)ptr2 = (__int64)(4);
                    ptr2->field_10 = 4;
                    ptr2->field_20 = 4;
                    ptr2->field_30 = 4;
                    ptr2->field_40 = 0;
                    result = (struct Struct_1_t *)v_d0;
                    v_84 = (__int64)result;
                    xmm0 = _mm_load_si128((__m128i *)&v_90);
                    xmm1 = _mm_load_si128((__m128i *)&v_a0);
                    xmm2 = _mm_load_si128((__m128i *)&v_b0);
                    xmm3 = _mm_load_si128((__m128i *)&v_c0);
                    _mm_storeu_si128((__m128i *)&v_74, xmm3);
                    _mm_storeu_si128((__m128i *)&v_64, xmm2);
                    _mm_storeu_si128((__m128i *)&v_54, xmm1);
                    _mm_storeu_si128((__m128i *)&v_44, xmm0);
                    *dst = 186;
                    *(dst + 2) = 160;
                    return _mm_cvtsi128_si64(xmm3);
                }
                break;
            case 116:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 179;
                return v_30;
            case 117:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 221;
                return v_30;
            case 119:
                ptr2 = (struct Struct_3_t *)ptr3;
                dst = (__int64 *)a1;
                v_20 = 1;
                a1 = rsp + 64;
                ptr4 = (struct Struct_5_t *)result;
                sub_1400831E0(a1, a3, result, ptr);
                a2 = (int *)v_40;
                result = (struct Struct_1_t *)v_41;
                v_90 = (__int64)result;
                result = (struct Struct_1_t *)v_43;
                v_92 = (__int64)result;
                if (a2 == 4) JUMPOUT(0x14008a4db);
                result = (struct Struct_1_t *)v_4c;
                v_f8 = (__int64)result;
                result = (struct Struct_1_t *)v_44;
                v_f0 = (__int64)result;
                a3 = (size_t *)v_50;
                result = (struct Struct_1_t *)v_90;
                v_3c = (__int64)result;
                result = (struct Struct_1_t *)v_92;
                v_3e = (__int64)result;
                a1 = (size_t *)ptr2;
                a4 = ptr2->field_40;
                result = (struct Struct_1_t *)dst;
                if (ptr3 <= 3) {
                    i = ptr4->field_3;
                    v6 = ptr4->field_0;
                    a3 = (size_t *)((__int64)(__int64)a3 & 15);
                    i >>= 4;
                    ptr = (struct Struct_2_t *)v6;
                    ptr = (struct Struct_2_t *)((__int64)(__int64)ptr >> 1);
                    if (ptr4->field_2 != 0) ptr = i;
                    v6 &= 32;
                    i = 0;
                    ++i;
                    v6 = 3;
                    if (((__int64)dst & 1) == 0) v6 = i;
                    a4 = (size_t *)((__int64)(__int64)a4 << 4);
                    *(__int64 *)((__int64)a1 + (__int64)ptr3) = 0;
                    *(__int64 *)((__int64)a1 + (__int64)ptr3 + 1) = v6;
                    *(__int64 *)((__int64)a1 + (__int64)ptr3 + 2) = a3;
                    a3 = a1[8];
                    ++a3;
                    a1[8] = a3;
                    if (a3 <= 3) {
                        a3 = (size_t *)((__int64)(__int64)a3 << 4);
                        *(__int64 *)((__int64)a1 + (__int64)a3) = a2;
                        a2 = (int *)v_3e;
                        *(__int64 *)((__int64)a1 + (__int64)a3 + 3) = a2;
                        a2 = (int *)v_3c;
                        *(__int64 *)((__int64)a1 + (__int64)a3 + 1) = a2;
                        a2 = (int *)v_f0;
                        *(__int64 *)((__int64)a1 + (__int64)a3 + 4) = a2;
                        a2 = (int *)v_f8;
                        *(__int64 *)((__int64)a1 + (__int64)a3 + 12) = a2;
                        a1[8] = a1[8] + 1;
                    }
                }
                a2 = a1[8];
                v_d0 = (__int64)a2;
                xmm0 = _mm_loadu_si128((__m128i *)a1);
                xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
                xmm2 = _mm_loadu_si128((__m128i *)(a1 + 32));
                xmm3 = _mm_loadu_si128((__m128i *)(a1 + 48));
                _mm_store_si128((__m128i *)&v_c0, xmm3);
                _mm_store_si128((__m128i *)&v_b0, xmm2);
                _mm_store_si128((__m128i *)&v_a0, xmm1);
                _mm_store_si128((__m128i *)&v_90, xmm0);
                *a1 = 4;
                a1[2] = 4;
                a1[4] = 4;
                a1[6] = 4;
                a1[8] = 0;
                a1 = (size_t *)v_d0;
                v_84 = (__int64)a1;
                xmm0 = _mm_load_si128((__m128i *)&v_90);
                xmm1 = _mm_load_si128((__m128i *)&v_a0);
                xmm2 = _mm_load_si128((__m128i *)&v_b0);
                xmm3 = _mm_load_si128((__m128i *)&v_c0);
                _mm_storeu_si128((__m128i *)&v_74, xmm3);
                _mm_storeu_si128((__m128i *)&v_64, xmm2);
                _mm_storeu_si128((__m128i *)&v_54, xmm1);
                _mm_storeu_si128((__m128i *)&v_44, xmm0);
                *(__int64 *)result = (__int64)(186);
                result->field_2 = 262;
                xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                xmm1 = _mm_loadu_si128((__m128i *)&v_50);
                xmm2 = _mm_loadu_si128((__m128i *)&v_60);
                xmm3 = _mm_loadu_si128((__m128i *)&v_70);
                _mm_storeu_si128((__m128i *)(result + 36), xmm0);
                _mm_storeu_si128((__m128i *)(result + 52), xmm1);
                _mm_storeu_si128((__m128i *)(result + 68), xmm2);
                _mm_storeu_si128((__m128i *)(result + 84), xmm3);
                a1 = (size_t *)v_7c;
                result->field_60 = a1;
                a1 = (size_t *)v_84;
                result->field_68 = a1;
                break;
            case 122:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 246;
                return v_30;
            case 123:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 181;
                return v_30;
            case 126:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 252;
                return v_30;
            case 128:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 258;
                return v_30;
            case 131:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 259;
                return v_30;
            case 139:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 182;
                return v_30;
            case 143:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 183;
                return v_30;
            case 149:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 260;
                return v_30;
            case 150:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 261;
                return v_30;
            case 152:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 223;
                return v_30;
            case 153:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 224;
                return v_30;
            case 154:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 180;
                return v_30;
            case 155:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 225;
                return v_30;
            case 156:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 176;
                return v_30;
            case 157:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 177;
                return v_30;
            case 158:
                v_28 = i;
                v_20 = (__int64)ptr;
                v_30 = 178;
                sub_1400898F0(a1, a3, result);
                break;
            default:
                dst = (__int64 *)a1;
                v_20 = 0;
                ptr = (struct Struct_2_t *)a3;
                ptr2 = (struct Struct_3_t *)ptr3;
                sub_140083930(a3, result, ptr3, ptr);
                if (result != 6) {
                    return (__int64)ptr2;
                } else {
                    a1 = ptr->field_10;
                    result = (struct Struct_1_t *)dst;
                    if (a1 >= ptr->field_8) JUMPOUT(0x14008a6a1);
                    a2 = ptr->field_0;
                    a2 = *(__int64 *)((__int64)a2 + (__int64)a1);
                    ++a1;
                    ptr->field_10 = a1;
                    a1 = (size_t *)ptr2;
                    a3 = ptr2->field_40;
                    if (a3 <= 3) {
                        a3 = (size_t *)((__int64)(__int64)a3 << 4);
                        *(__int64 *)((__int64)a1 + (__int64)a3) = 2;
                        *(__int64 *)((__int64)a1 + (__int64)a3 + 8) = a2;
                        a1[8] = a1[8] + 1;
                    }
                    a2 = a1[8];
                    v_d0 = (__int64)a2;
                    xmm0 = _mm_loadu_si128((__m128i *)a1);
                    xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
                    xmm2 = _mm_loadu_si128((__m128i *)(a1 + 32));
                    xmm3 = _mm_loadu_si128((__m128i *)(a1 + 48));
                    _mm_store_si128((__m128i *)&v_c0, xmm3);
                    _mm_store_si128((__m128i *)&v_b0, xmm2);
                    _mm_store_si128((__m128i *)&v_a0, xmm1);
                    _mm_store_si128((__m128i *)&v_90, xmm0);
                    *a1 = 4;
                    a1[2] = 4;
                    a1[4] = 4;
                    a1[6] = 4;
                    a1[8] = 0;
                    a1 = (size_t *)v_d0;
                    v_84 = (__int64)a1;
                    xmm0 = _mm_load_si128((__m128i *)&v_90);
                    xmm1 = _mm_load_si128((__m128i *)&v_a0);
                    xmm2 = _mm_load_si128((__m128i *)&v_b0);
                    xmm3 = _mm_load_si128((__m128i *)&v_c0);
                    _mm_storeu_si128((__m128i *)&v_74, xmm3);
                    _mm_storeu_si128((__m128i *)&v_64, xmm2);
                    _mm_storeu_si128((__m128i *)&v_54, xmm1);
                    _mm_storeu_si128((__m128i *)&v_44, xmm0);
                    *(__int64 *)result = (__int64)(186);
                    result->field_2 = 187;
                    return _mm_cvtsi128_si64(xmm3);
                }
                break;
        }
        return _mm_cvtsi128_si64(xmm3);
    }
    return (__int64)result;
}