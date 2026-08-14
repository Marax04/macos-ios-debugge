// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_14004F470();
__int64 sub_1400685B0();
__int64 sub_140055430();
extern __int64 off_140116BA8;
extern __int64 off_140116676;

__int64 __fastcall sub_1400675A0(int *a1, int *a2, __int64 a3, int *a4) {
    __int64 rsp;
    int v_100;
    int v_108;
    int v_118;
    int v_120;
    int v_128;
    int v_130;
    int v_138;
    int v_140;
    int v_144;
    int v_148;
    int v_150;
    int v_158;
    int v_168;
    int v_170;
    int v_178;
    int v_180;
    int v_188;
    int v_190;
    int v_20;
    int v_28;
    int v_29;
    int v_2d;
    int v_2f;
    __int64 v_30;
    int v_38;
    int v_48;
    int v_50;
    int v_54;
    int v_58;
    int v_60;
    int v_70;
    int v_80;
    int v_88;
    int v_90;
    int v_98;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_b9;
    int v_bd;
    int v_bf;
    int v_c0;
    int v_c8;
    int v_d8;
    int v_e0;
    int v_f8;
    __int64 *v_10;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 *i;
    __int64 v8;
    __int64 v7;
    __int64 *i2;
    __m128i xmm0;
    __int64 v5;
    __int64 v6;
    __m128i xmm1;

    ptr2 = (struct Struct_2_t *)a2;
    ptr = (struct Struct_1_t *)a1;
    v_f8 = 0x2D2B;
    v_100 = 0x393100;
    v_108 = 0;
    v_118 = 0;
    v_120 = 95;
    v_128 = 2;
    result = &off_140116BA8;
    v_130 = result;
    v_138 = 5;
    v_140 = 3;
    result = &off_140116676;
    v_148 = result;
    v_150 = 7;
    result = v_140;
    v_50 = result;
    result = v_144;
    v_54 = result;
    result = v_148;
    v_58 = result;
    v_60 = 7;
    i = a2[2];
    v8 = a2[3];
    if (v8 != 0) {
        result = *i;
        v7 = v8 - 1;
        i2 = i + 1;
        if (result != 43) {
            if (result != 45) {
                xmm0 = _mm_setzero_si128();
                _mm_storeu_si128((__m128i *)&v_38, xmm0);
                v_20 = 1;
                v_28 = 0;
                v_30 = 8;
                a1 = rsp + 32;
                sub_14004F470(a1);
                v7 = v8;
                i2 = i;
            }
        }
        if (v7 != 0) {
            result = *i2;
            a1 = v7 - 1;
            a2 = i2 + 1;
            ptr2->field_10 = a2;
            ptr2->field_18 = a1;
            result += 207;
            if (result >= 9) {
                xmm0 = _mm_setzero_si128();
                _mm_store_si128((__m128i *)&v_70, xmm0);
                a1 = 8;
                result = 0;
            } else {
                result = rsp + 264;
                v_158 = 0;
                v_168 = result;
                v_170 = 0;
                a1 = rsp + 32;
                a2 = rsp + 344;
                sub_1400685B0(a1, a2, ptr2);
                a2 = (int *)v_20;
                if (a2 != 3) {
                    result = v_28;
                    a1 = (int *)v_2f;
                    a1 = (int *)((__int64)(__int64)a1 << 16);
                    a3 = v_2d;
                    a3 |= (__int64)a1;
                    a3 <<= 32;
                    a4 = (int *)v_29;
                    a4 = (int *)((__int64)(__int64)a4 | a3);
                    a1 = (int *)v_30;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_38);
                    _mm_store_si128((__m128i *)&v_70, xmm0);
                    a3 = v_48;
                    if (a2 == 1) {
                        a2 = a4;
                        a2 = (int *)((__int64)(__int64)a2 >> 32);
                        v5 = (__int64)a4;
                        v5 >>= 48;
                        v_b0 = 1;
                        v_b8 = result;
                        v_b9 = (int)a4;
                        v_bf = v5;
                        v_bd = (int)a2;
                        v_c0 = (int)a1;
                        xmm0 = _mm_load_si128((__m128i *)&v_70);
                        _mm_storeu_si128((__m128i *)&v_c8, xmm0);
                        v_d8 = a3;
                        ptr2->field_10 = i2;
                        ptr2->field_18 = v7;
                        if (v7 != 0) {
                            result = *i2;
                            result += 208;
                            if (result > 9) {
                                xmm0 = _mm_setzero_si128();
                                _mm_storeu_si128((__m128i *)&v_190, xmm0);
                                v_178 = 1;
                                v_180 = 0;
                                v_188 = 8;
                                a1 = rsp + 128;
                                a2 = rsp + 176;
                                a3 = rsp + 376;
                                sub_140055430(a1, a2, a3);
                                a2 = (int *)v_80;
                                result = v_88;
                                a4 = (int *)result;
                                a4 = (int *)((__int64)(__int64)a4 >> 8);
                                a1 = (int *)v_90;
                                xmm0 = _mm_loadu_si128((__m128i *)&v_98);
                                _mm_store_si128((__m128i *)&v_e0, xmm0);
                                a3 = v_a8;
                                a4 = (int *)((__int64)(__int64)a4 << 8);
                                v6 = (__int64)a4;
                                v6 &= -65536;
                                result |= (__int64)a4;
                                result |= v6;
                                *(__int64 *)ptr = (__int64)(a2);
                                ptr2 = ptr + 16;
                                ptr->field_10 = a1;
                                xmm0 = _mm_load_si128((__m128i *)&v_e0);
                                _mm_storeu_si128((__m128i *)(ptr + 24), xmm0);
                                ptr->field_28 = a3;
                                if (a2 != 0) {
                                    v_20 = result;
                                    xmm0 = _mm_loadu_si128((__m128i *)ptr2);
                                    xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + 16));
                                    _mm_storeu_si128((__m128i *)&v_28, xmm0);
                                    _mm_storeu_si128((__m128i *)&v_38, xmm1);
                                    i = (__int64 *)v_30;
                                    if (i == result) JUMPOUT(0x14006798c);
                                    a1 = rsp + 40;
                                    a2 = (int *)v_28;
                                    a3 = i + (__int64)(__int64)i*2;
                                    a4 = (int *)v_60;
                                    v_10[a3] = a4;
                                    xmm0 = _mm_load_si128((__m128i *)&v_50);
                                    _mm_storeu_si128((__m128i *)(a2 + a3*8), xmm0);
                                    ++i;
                                    v_30 = (__int64)i;
                                    xmm0 = _mm_loadu_si128((__m128i *)a1);
                                    xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
                                    _mm_store_si128((__m128i *)&v_90, xmm1);
                                    _mm_store_si128((__m128i *)&v_80, xmm0);
                                }
                                ptr->field_8 = result;
                                xmm0 = _mm_load_si128((__m128i *)&v_80);
                                xmm1 = _mm_load_si128((__m128i *)&v_90);
                                _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
                                _mm_storeu_si128((__m128i *)ptr2, xmm0);
                            } else {
                                ++i2;
                                a1 = rsp + 176;
                                sub_14004F470(a1, a2, a3, 0);
                                i2 = (__int64 *)((__int64)i2 - (__int64)i);
                                v8 -= (__int64)i2;
                                if ((v8 < 0)) JUMPOUT(0x1400679a0);
                                result = (__int64)i + (__int64)i2;
                                ptr2->field_10 = result;
                                ptr2->field_18 = v8;
                                ptr->field_8 = i;
                                ptr->field_10 = i2;
                                *(__int64 *)ptr = (__int64)(3);
                            }
                            return result;
                        }
                        return result;
                    } else {
                        xmm0 = _mm_load_si128((__m128i *)&v_70);
                        _mm_store_si128((__m128i *)&v_e0, xmm0);
                    }
                    return _mm_cvtsi128_si64(xmm0);
                } else {
                    i2 = ptr2->field_10;
                }
                return (__int64)i2;
            }
            return (__int64)i2;
        }
        return (__int64)i2;
    }
    return result;
}