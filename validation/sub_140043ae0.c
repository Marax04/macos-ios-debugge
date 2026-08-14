// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int64 field_3D0; // offset 976
};

// inferred from 2 accesses on `a3`
struct Struct_3_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int64 field_3D0; // offset 976
};

// inferred from 2 accesses on `result`
struct Struct_4_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[616];
    __int64 field_3D0; // offset 976
};

// inferred from 4 accesses on `i`
struct Struct_5_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
};

__int64 sub_1400F37D0();
__int64 sub_1400F27F6();
__int64 sub_1400F27F0();
__int64 sub_1400442B4();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401147A0;
extern __int64 off_1401147D0;
extern __int64 off_14011D858;
extern __int64 off_140114570;

__int64 __fastcall sub_140043AE0(struct Struct_1_t *a1,struct Struct_2_t *a2,struct Struct_3_t *a3) {
    __int64 arg_10;
    __int64 arg_18;
    int arg_20;
    __int64 arg_26;
    int arg_30;
    int arg_40;
    int arg_50;
    int arg_58;
    int arg_68;
    int arg_78;
    __int64 arg_8;
    __int64 arg_80;
    int arg_88;
    int arg_90;
    __int64 v_10;
    __int64 v_18;
    int v_20;
    __int64 v_30;
    int v_40;
    int v_50;
    int v_60;
    __int64 src;
    char *dst;
    __int64 *dst2;
    __int64 v8;
    __int64 *src2;
    struct Struct_4_t *result;
    __int64 *v11;
    __int64 *dst3;
    __int64 *dst4;
    struct Struct_5_t *i;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v10;
    __int64 v6;
    __int64 v7;
    __m128i xmm3;

    dst2 = ((__int64 *)a1)[3];
    v8 = *(dst2 + 978);
    src2 = ((__int64 *)a1)[5];
    result = *(src2 + 978);
    v11 = (__int64 *)result;
    a2 = v8 + v11;
    ++a2;
    if (a2 >= 12) {
        a1 = &off_1401147A0;
        a3 = &off_1401147D0;
        sub_1400F37D0(a1, 42, a3);
    } else {
        arg_26 = (__int64)result;
        dst3 = a1->field_0;
        result = a1->field_8;
        v_18 = (__int64)result;
        result = ((__int64 *)a1)[4];
        src = (__int64)result;
        dst4 = v8 + 1;
        arg_18 = (__int64)src2;
        src2 = *(dst3 + 978);
        v_10 = (__int64)src2;
        i = ((__int64 *)a1)[2];
        v_20 = (int)a2;
        *(dst2 + 978) = a2;
        result = (__int64)(__int64)i * 56;
        a1 = (__int64)dst3 + (__int64)result;
        a1 += 360;
        a2 = *(__int64 *)((__int64)dst3 + (__int64)result + 408);
        v_30 = (__int64)a2;
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 360));
        xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 376));
        xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 392));
        _mm_store_si128((__m128i *)&v_40, xmm2);
        _mm_store_si128((__m128i *)&v_50, xmm1);
        _mm_store_si128((__m128i *)&v_60, xmm0);
        a2 = (__int64)dst3 + (__int64)result;
        a2 += 416;
        v10 = (__int64)i;
        v10 = ~v10;
        v10 += (__int64)src2;
        a3 = v10 * 56;
        sub_1400F27F6(a1, a2, a3, src2);
        result = v8 * 56;
        xmm0 = _mm_load_si128((__m128i *)&v_60);
        xmm1 = _mm_load_si128((__m128i *)&v_50);
        xmm2 = _mm_load_si128((__m128i *)&v_40);
        _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 360), xmm0);
        _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 376), xmm1);
        _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 392), xmm2);
        a1 = (struct Struct_1_t *)v_30;
        *(__int64 *)((__int64)dst2 + (__int64)result + 408) = a1;
        result = (struct Struct_4_t *)arg_18;
        a2 = result + 360;
        result = (__int64)(__int64)dst4 * 56;
        a1 = (__int64)dst2 + (__int64)result;
        a1 += 360;
        a3 = (__int64)(__int64)v11 * 56;
        sub_1400F27F0(a1, a2, a3);
        result = (struct Struct_4_t *)i;
        result = (struct Struct_4_t *)((__int64)(__int64)result << 5);
        a1 = (__int64)dst3 + (__int64)result;
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result));
        xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 16));
        _mm_store_si128((__m128i *)&v_50, xmm1);
        _mm_store_si128((__m128i *)&v_60, xmm0);
        a2 = (__int64)dst3 + (__int64)result;
        a2 += 32;
        a3 = (struct Struct_3_t *)v10;
        a3 = (struct Struct_3_t *)((__int64)(__int64)a3 << 5);
        sub_1400F27F6(a1, a2, a3);
        *dst = v8;
        result = (struct Struct_4_t *)v8;
        result = (struct Struct_4_t *)((__int64)(__int64)result << 5);
        xmm0 = _mm_load_si128((__m128i *)&v_60);
        xmm1 = _mm_load_si128((__m128i *)&v_50);
        _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result), xmm0);
        _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 16), xmm1);
        a1 = (struct Struct_1_t *)dst4;
        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 << 5);
        a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst2);
        arg_10 = (__int64)v11;
        a3 = (struct Struct_3_t *)v11;
        a3 = (struct Struct_3_t *)((__int64)(__int64)a3 << 5);
        a2 = (struct Struct_2_t *)arg_18;
        sub_1400F27F0(a1, a2, a3);
        v8 = i + 1;
        v11 = dst3 + (__int64)(__int64)i*8;
        v11 += 992;
        arg_8 = (__int64)i;
        a2 = dst3 + (__int64)(__int64)i*8;
        a2 += 1000;
        v10 <<= 3;
        sub_1400F27F6(v11, a2, v10);
        v6 = v_10;
        if (v8 < v6) {
            a2 = (struct Struct_2_t *)arg_8;
            result = (struct Struct_4_t *)a2;
            result = (struct Struct_4_t *)(~(__int64)result);
            a1 = v6 + result;
            result = (struct Struct_4_t *)v6;
            result = (struct Struct_4_t *)((__int64)result - (__int64)a2);
            result -= 2;
            a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 3);
            if (!((a1 == 0))) {
                for (a2 = 0; a1 != a2; ++a2) {
                    a3 = v11[(__int64)a2];
                    a3->field_160 = dst3;
                    src2 = v8 + a2;
                    a3->field_3D0 = src2;
                }
                v8 += (__int64)a2;
            }
            if (result >= 3) {
                do {
                    result = *(dst3 + v8*8 + 984);
                    result->field_160 = dst3;
                    result->field_3D0 = v8;
                    result = *(dst3 + v8*8 + 992);
                    result->field_160 = dst3;
                    a1 = v8 + 1;
                    result->field_3D0 = a1;
                    result = *(dst3 + v8*8 + 1000);
                    result->field_160 = dst3;
                    a1 = v8 + 2;
                    result->field_3D0 = a1;
                    result = *(dst3 + v8*8 + 1008);
                    result->field_160 = dst3;
                    a1 = v8 + 3;
                    result->field_3D0 = a1;
                    v8 += 4;
                } while (v8 != v6);
            }
        }
        *(dst3 + 978) = *(dst3 + 978) - 1;
        dst3 = (__int64 *)arg_18;
        v10 = v_20;
        if (v_18 >= 2) {
            i = (struct Struct_5_t *)arg_10;
            ++i;
            result = (struct Struct_4_t *)v10;
            v11 = *dst;
            result = (struct Struct_4_t *)((__int64)result - (__int64)v11);
            if (i != result) {
                a1 = &off_14011D858;
                a3 = &off_140114570;
                sub_1400F37D0(a1, 40, a3);
                dst4 = ((__int64 *)a1)[3];
                src2 = *(dst4 + 978);
                result = (__int64)a2 + (__int64)src2;
                if (result >= 12) JUMPOUT(0x1400442f2);
                i = (struct Struct_5_t *)a1;
                dst2 = ((__int64 *)a1)[5];
                v11 = *(dst2 + 978);
                v11 = (__int64 *)((__int64)v11 - (__int64)a2);
                if ((v11 < 0)) JUMPOUT(0x14004430a);
                *(dst4 + 978) = result;
                *(dst2 + 978) = v11;
                dst3 = (__int64)(__int64)a2 * 56;
                arg_88 = (int)a2;
                v10 = (__int64)a2;
                v10 <<= 5;
                xmm0 = _mm_loadu_si128((__m128i *)(dst2 + v10 - 32));
                xmm1 = _mm_loadu_si128((__m128i *)(dst2 + v10 - 16));
                _mm_store_si128((__m128i *)&arg_10, xmm1);
                _mm_store_si128((__m128i *)&*dst, xmm0);
                result = i->field_0;
                a1 = i->field_10;
                v7 = (__int64)(__int64)a1 * 56;
                a3 = *(__int64 *)(result + v7 + 408);
                arg_50 = (int)a3;
                xmm0 = _mm_loadu_si128((__m128i *)(result + v7 + 360));
                xmm1 = _mm_loadu_si128((__m128i *)(result + v7 + 376));
                xmm2 = _mm_loadu_si128((__m128i *)(result + v7 + 392));
                _mm_store_si128((__m128i *)&arg_40, xmm2);
                _mm_store_si128((__m128i *)&arg_30, xmm1);
                _mm_store_si128((__m128i *)&arg_20, xmm0);
                a3 = *(__int64 *)((__int64)dst2 + (__int64)dst3 + 352);
                xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)dst3 + 304));
                xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)dst3 + 320));
                xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)dst3 + 336));
                *(__int64 *)(result + v7 + 408) = (__int64)(a3);
                a2 = dst2 + 360;
                arg_78 = (int)a2;
                _mm_storeu_si128((__m128i *)(result + v7 + 360), xmm0);
                _mm_storeu_si128((__m128i *)(result + v7 + 392), xmm2);
                _mm_storeu_si128((__m128i *)(result + v7 + 376), xmm1);
                a3 = dst3 - 56;
                a1 = (struct Struct_1_t *)((__int64)(__int64)a1 << 5);
                xmm0 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)a1));
                xmm1 = _mm_loadu_si128((__m128i *)((__int64)result + (__int64)a1 + 16));
                _mm_storeu_si128((__m128i *)&arg_68, xmm1);
                _mm_storeu_si128((__m128i *)&arg_58, xmm0);
                xmm0 = _mm_load_si128((__m128i *)&*dst);
                xmm1 = _mm_load_si128((__m128i *)&arg_10);
                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a1 + 16), xmm1);
                _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a1), xmm0);
                result = (struct Struct_4_t *)arg_50;
                v_30 = (__int64)result;
                xmm0 = _mm_load_si128((__m128i *)&arg_20);
                xmm1 = _mm_load_si128((__m128i *)&arg_30);
                xmm2 = _mm_load_si128((__m128i *)&arg_40);
                _mm_store_si128((__m128i *)&v_40, xmm2);
                _mm_store_si128((__m128i *)&v_50, xmm1);
                _mm_store_si128((__m128i *)&v_60, xmm0);
                xmm3 = _mm_loadu_si128((__m128i *)&arg_68);
                _mm_store_si128((__m128i *)&v_10, xmm3);
                xmm3 = _mm_loadu_si128((__m128i *)&arg_58);
                _mm_store_si128((__m128i *)&v_20, xmm3);
                a1 = (__int64)(__int64)src2 * 56;
                *(__int64 *)((__int64)dst4 + (__int64)a1 + 408) = result;
                _mm_storeu_si128((__m128i *)((__int64)dst4 + (__int64)a1 + 392), xmm2);
                _mm_storeu_si128((__m128i *)((__int64)dst4 + (__int64)a1 + 376), xmm1);
                _mm_storeu_si128((__m128i *)((__int64)dst4 + (__int64)a1 + 360), xmm0);
                result = (struct Struct_4_t *)src2;
                result = (struct Struct_4_t *)((__int64)(__int64)result << 5);
                xmm0 = _mm_load_si128((__m128i *)&v_20);
                xmm1 = _mm_load_si128((__m128i *)&v_10);
                _mm_storeu_si128((__m128i *)((__int64)dst4 + (__int64)result + 16), xmm1);
                _mm_storeu_si128((__m128i *)((__int64)dst4 + (__int64)result), xmm0);
                arg_80 = (__int64)src2;
                v8 = src2 + 1;
                a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst4);
                a1 += 416;
                sub_1400F27F0(a1, a2, a3, src2);
                arg_90 = v8;
                a1 = (struct Struct_1_t *)v8;
                a1 = (struct Struct_1_t *)((__int64)(__int64)a1 << 5);
                a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst4);
                a3 = v10 - 32;
                sub_1400F27F0(a1, dst2, a3);
                a2 = (__int64)dst2 + (__int64)dst3;
                a2 += 360;
                a3 = (__int64)(__int64)v11 * 56;
                a1 = (struct Struct_1_t *)arg_78;
                sub_1400F27F6(a1, a2, a3);
                v10 += (__int64)dst2;
                a3 = (struct Struct_3_t *)v11;
                a3 = (struct Struct_3_t *)((__int64)(__int64)a3 << 5);
                sub_1400F27F6(dst2, v10, a3);
                result = i->field_30;
                if (i->field_20 == 0) JUMPOUT(0x140044210);
                if (result == 0) JUMPOUT(0x140044219);
                i = dst2 + 984;
                v10 = arg_90;
                a1 =  + v10*8 + 984;
                a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst4);
                dst3 = (__int64 *)arg_88;
                a3 =  + (__int64)(__int64)dst3*8;
                sub_1400F27F0(a1, i, a3);
                a2 = dst2 + (__int64)(__int64)dst3*8;
                a2 += 984;
                a3 =  + (__int64)(__int64)v11*8 + 8;
                sub_1400F27F6(i, a2, a3);
                a2 = (struct Struct_2_t *)arg_80;
                result = *(dst4 + (__int64)(__int64)a2*8 + 992);
                result->field_160 = dst4;
                result->field_3D0 = v10;
                if (dst3 != 1) {
                    result = *(dst4 + (__int64)(__int64)a2*8 + 1000);
                    result->field_160 = dst4;
                    a1 = a2 + 2;
                    result->field_3D0 = a1;
                    if (dst3 != 2) {
                        result = *(dst4 + (__int64)(__int64)a2*8 + 1008);
                        result->field_160 = dst4;
                        a1 = a2 + 3;
                        result->field_3D0 = a1;
                        if (dst3 != 3) {
                            result = *(dst4 + (__int64)(__int64)a2*8 + 1016);
                            result->field_160 = dst4;
                            a1 = a2 + 4;
                            result->field_3D0 = a1;
                            if (dst3 != 4) {
                                result = *(dst4 + (__int64)(__int64)a2*8 + 0x400);
                                result->field_160 = dst4;
                                a1 = a2 + 5;
                                result->field_3D0 = a1;
                            }
                        }
                    }
                }
                a2 = v11 + 1;
                result = (struct Struct_4_t *)a2;
                result = (struct Struct_4_t *)((__int64)(__int64)result & 3);
                if (v11 >= 3) JUMPOUT(0x140044231);
                a1 = 0;
                return sub_1400442B4();
            } else {
                result = dst2 + 984;
                a1 = result + (__int64)(__int64)dst4*8;
                a2 = dst3 + 984;
                a3 =  + (__int64)(__int64)i*8;
                sub_1400F27F0(a1, a2, a3, src2);
                i = (struct Struct_5_t *)((__int64)(__int64)i & 3);
                if (!((i == 0))) {
                    a1 = dst2 + (__int64)(__int64)v11*8;
                    a1 += 992;
                    for (result = 0; i != result; ++result) {
                        a2 = ((__int64 *)a1)[(__int64)result];
                        a2->field_160 = dst2;
                        a3 = (__int64)result + (__int64)dst4;
                        a2->field_3D0 = a3;
                    }
                    dst4 = (__int64 *)((__int64)dst4 + (__int64)result);
                }
                if (arg_26 >= 3) {
                    do {
                        result = *(dst2 + (__int64)(__int64)dst4*8 + 984);
                        result->field_160 = dst2;
                        result->field_3D0 = dst4;
                        result = *(dst2 + (__int64)(__int64)dst4*8 + 992);
                        result->field_160 = dst2;
                        a1 = dst4 + 1;
                        result->field_3D0 = a1;
                        result = *(dst2 + (__int64)(__int64)dst4*8 + 1000);
                        result->field_160 = dst2;
                        a1 = dst4 + 2;
                        result->field_3D0 = a1;
                        result = *(dst2 + (__int64)(__int64)dst4*8 + 1008);
                        result->field_160 = dst2;
                        a1 = dst4 + 3;
                        result->field_3D0 = a1;
                        dst4 += 4;
                    } while (a1 != v10);
                }
            }
        }
        off_140108030(a1, a2, a3);
        off_140108038(result, 0, dst3);
        result = (struct Struct_4_t *)dst2;
        a2 = (struct Struct_2_t *)src;
        return (__int64)a2;
    }
    return (__int64)result;
}