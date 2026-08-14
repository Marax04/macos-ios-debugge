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

// inferred from 4 accesses on `ptr`
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
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401145D0;
extern __int64 off_140114608;
extern __int64 off_14011B078;
extern __int64 off_140114620;
extern __int64 off_14011B42B;
extern __int64 off_140114638;
extern __int64 off_14011D858;
extern __int64 off_140114570;

__int64 __fastcall sub_140043700(struct Struct_1_t *a1,struct Struct_2_t *a2,struct Struct_3_t *a3) {
    __int64 arg_10;
    __int64 arg_18;
    int arg_20;
    __int64 arg_26;
    int arg_30;
    int arg_40;
    __int64 arg_50;
    int arg_58;
    int arg_68;
    __int64 arg_8;
    int arg_80;
    __int64 arg_88;
    __int64 arg_90;
    int arg_98;
    __int64 arg_a0;
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
    struct Struct_4_t *result;
    __int64 v8;
    __int64 *dst3;
    __int64 *dst4;
    __int64 v10;
    __int64 *src2;
    __int64 *i;
    __int64 *v11;
    __m128i xmm0;
    __m128i xmm1;
    struct Struct_5_t *ptr;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v7;

    dst2 = ((__int64 *)a1)[5];
    result = *(dst2 + 978);
    arg_a0 = (__int64)result;
    v8 = (__int64)a2 + (__int64)result;
    if (v8 >= 12) {
        a1 = &off_1401145D0;
        a3 = &off_140114608;
        sub_1400F37D0(a1, 51, a3, src2);
    } else {
        dst3 = ((__int64 *)a1)[3];
        dst4 = *(dst3 + 978);
        v10 = (__int64)dst4;
        v10 -= (__int64)a2;
        if ((v10 < 0)) {
            a1 = &off_14011B078;
            a3 = &off_140114620;
            sub_1400F37D0(a1, 39, a3);
        } else {
            arg_80 = (int)a1;
            *(dst3 + 978) = v10;
            *(dst2 + 978) = v8;
            src2 = dst2 + 360;
            i = (__int64 *)a2;
            result = (__int64)(__int64)a2 * 56;
            a1 = (__int64)dst2 + (__int64)result;
            a1 += 360;
            v11 = (__int64 *)arg_a0;
            a3 = (__int64)(__int64)v11 * 56;
            arg_88 = (__int64)src2;
            sub_1400F27F6(a1, src2, a3, src2);
            a1 = (struct Struct_1_t *)i;
            a1 = (struct Struct_1_t *)((__int64)(__int64)a1 << 5);
            a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst2);
            a3 = (struct Struct_3_t *)v11;
            a3 = (struct Struct_3_t *)((__int64)(__int64)a3 << 5);
            sub_1400F27F6(a1, dst2, a3);
            v11 = v10 + 1;
            dst4 = (__int64 *)((__int64)dst4 - (__int64)v11);
            arg_90 = (__int64)i;
            result = i - 1;
            if (dst4 == result) {
                arg_98 = v8;
                result = (__int64)(__int64)v11 * 56;
                a2 = (__int64)result + (__int64)dst3;
                a2 += 360;
                v8 = (__int64)(__int64)dst4 * 56;
                i = (__int64 *)arg_88;
                sub_1400F27F0(i, a2, v8);
                a2 = (struct Struct_2_t *)v11;
                a2 = (struct Struct_2_t *)((__int64)(__int64)a2 << 5);
                a2 = (struct Struct_2_t *)((__int64)a2 + (__int64)dst3);
                dst4 = (__int64 *)((__int64)(__int64)dst4 << 5);
                sub_1400F27F0(dst2, a2, dst4);
                result = v10 * 56;
                v10 <<= 5;
                xmm0 = _mm_loadu_si128((__m128i *)(dst3 + v10));
                xmm1 = _mm_loadu_si128((__m128i *)(dst3 + v10 + 16));
                _mm_store_si128((__m128i *)&*dst, xmm0);
                _mm_store_si128((__m128i *)&arg_10, xmm1);
                ptr = (struct Struct_5_t *)arg_80;
                a1 = ptr->field_0;
                a2 = ptr->field_10;
                a3 = (__int64)(__int64)a2 * 56;
                a2 = (struct Struct_2_t *)((__int64)(__int64)a2 << 5);
                src2 = *(__int64 *)((__int64)a1 + (__int64)a3 + 408);
                arg_50 = (__int64)src2;
                xmm0 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 360));
                xmm1 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 376));
                xmm2 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 392));
                _mm_store_si128((__m128i *)&arg_40, xmm2);
                _mm_store_si128((__m128i *)&arg_30, xmm1);
                _mm_store_si128((__m128i *)&arg_20, xmm0);
                src2 = *(__int64 *)((__int64)dst3 + (__int64)result + 408);
                xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 360));
                xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 376));
                xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 392));
                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 360), xmm0);
                *(__int64 *)((__int64)a1 + (__int64)a3 + 408) = src2;
                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 392), xmm2);
                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 376), xmm1);
                xmm0 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a2));
                xmm1 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a2 + 16));
                _mm_storeu_si128((__m128i *)&arg_68, xmm1);
                _mm_storeu_si128((__m128i *)&arg_58, xmm0);
                xmm0 = _mm_load_si128((__m128i *)&*dst);
                xmm1 = _mm_load_si128((__m128i *)&arg_10);
                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)a2 + 16), xmm1);
                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)a2), xmm0);
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
                *(i + v8 + 48) = result;
                _mm_storeu_si128((__m128i *)(i + v8 + 32), xmm2);
                _mm_storeu_si128((__m128i *)(i + v8 + 16), xmm1);
                _mm_storeu_si128((__m128i *)(i + v8), xmm0);
                xmm0 = _mm_load_si128((__m128i *)&v_20);
                xmm1 = _mm_load_si128((__m128i *)&v_10);
                _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)dst4 + 16), xmm1);
                _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)dst4), xmm0);
                result = ptr->field_30;
                if (ptr->field_20 == 0) {
                    if (result != 0) {
                        a1 = &off_14011B42B;
                        a3 = &off_140114638;
                        sub_1400F37D0(a1, 40, a3);
                        a2 = (struct Struct_2_t *)((__int64)(__int64)a2 & 60);
                        a1 = 0;
                        do {
                            a3 = *(dst2 + (__int64)(__int64)a1*8 + 984);
                            a3->field_160 = dst2;
                            src2 = (__int64 *)a1;
                            a3->field_3D0 = a1;
                            a3 = *(dst2 + (__int64)(__int64)a1*8 + 992);
                            a3->field_160 = dst2;
                            ptr = src2 + 1;
                            a3->field_3D0 = ptr;
                            a3 = *(dst2 + (__int64)(__int64)a1*8 + 1000);
                            a3->field_160 = dst2;
                            ptr = src2 + 2;
                            a3->field_3D0 = ptr;
                            a3 = *(dst2 + (__int64)(__int64)a1*8 + 1008);
                            a1 += 4;
                            a3->field_160 = dst2;
                            src2 += 3;
                            a3->field_3D0 = src2;
                        } while (a1 != a2);
                        if (result != 0) {
                            do {
                                a2 = *(dst2 + (__int64)(__int64)a1*8 + 984);
                                a2->field_160 = dst2;
                                a2->field_3D0 = a1;
                                ++a1;
                                --result;
                            } while ((result != 0));
                        }
                    }
                } else {
                    if (result == 0) {
                        return (__int64)result;
                    } else {
                        i = dst2 + 984;
                        dst4 = (__int64 *)arg_90;
                        a1 = dst2 + (__int64)(__int64)dst4*8;
                        a1 += 984;
                        v10 = arg_a0;
                        a3 =  + v10*8 + 8;
                        sub_1400F27F6(a1, i, a3, src2);
                        a2 =  + (__int64)(__int64)v11*8 + 984;
                        a2 = (struct Struct_2_t *)((__int64)a2 + (__int64)dst3);
                        a3 =  + (__int64)(__int64)dst4*8;
                        sub_1400F27F0(i, a2, a3);
                        a2 = dst4 + v10;
                        ++a2;
                        result = (struct Struct_4_t *)a2;
                        result = (struct Struct_4_t *)((__int64)(__int64)result & 3);
                        if (arg_98 >= 3) {
                            return (__int64)result;
                        } else {
                            a1 = 0;
                        }
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                }
                return (__int64)a1;
            }
        }
        a1 = &off_14011D858;
        a3 = &off_140114570;
        sub_1400F37D0(a1, 40, a3);
        dst2 = ((__int64 *)a1)[3];
        v8 = *(dst2 + 978);
        src2 = ((__int64 *)a1)[5];
        result = *(src2 + 978);
        v11 = (__int64 *)result;
        a2 = v8 + v11;
        ++a2;
        if (a2 >= 12) JUMPOUT(0x140043ebd);
        arg_26 = (__int64)result;
        dst4 = a1->field_0;
        result = a1->field_8;
        v_18 = (__int64)result;
        result = ((__int64 *)a1)[4];
        src = (__int64)result;
        dst3 = v8 + 1;
        arg_18 = (__int64)src2;
        src2 = *(dst4 + 978);
        v_10 = (__int64)src2;
        i = ((__int64 *)a1)[2];
        v_20 = (int)a2;
        *(dst2 + 978) = a2;
        result = (__int64)(__int64)i * 56;
        a1 = (__int64)dst4 + (__int64)result;
        a1 += 360;
        a2 = *(__int64 *)((__int64)dst4 + (__int64)result + 408);
        v_30 = (__int64)a2;
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst4 + (__int64)result + 360));
        xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst4 + (__int64)result + 376));
        xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst4 + (__int64)result + 392));
        _mm_store_si128((__m128i *)&v_40, xmm2);
        _mm_store_si128((__m128i *)&v_50, xmm1);
        _mm_store_si128((__m128i *)&v_60, xmm0);
        a2 = (__int64)dst4 + (__int64)result;
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
        result = (__int64)(__int64)dst3 * 56;
        a1 = (__int64)dst2 + (__int64)result;
        a1 += 360;
        a3 = (__int64)(__int64)v11 * 56;
        sub_1400F27F0(a1, a2, a3);
        result = (struct Struct_4_t *)i;
        result = (struct Struct_4_t *)((__int64)(__int64)result << 5);
        a1 = (__int64)dst4 + (__int64)result;
        xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst4 + (__int64)result));
        xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst4 + (__int64)result + 16));
        _mm_store_si128((__m128i *)&v_50, xmm1);
        _mm_store_si128((__m128i *)&v_60, xmm0);
        a2 = (__int64)dst4 + (__int64)result;
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
        a1 = (struct Struct_1_t *)dst3;
        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 << 5);
        a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst2);
        arg_10 = (__int64)v11;
        a3 = (struct Struct_3_t *)v11;
        a3 = (struct Struct_3_t *)((__int64)(__int64)a3 << 5);
        a2 = (struct Struct_2_t *)arg_18;
        sub_1400F27F0(a1, a2, a3);
        v8 = i + 1;
        v11 = dst4 + (__int64)(__int64)i*8;
        v11 += 992;
        arg_8 = (__int64)i;
        a2 = dst4 + (__int64)(__int64)i*8;
        a2 += 1000;
        v10 <<= 3;
        sub_1400F27F6(v11, a2, v10);
        v7 = v_10;
        if (v8 < v7) {
            a2 = (struct Struct_2_t *)arg_8;
            result = (struct Struct_4_t *)a2;
            result = (struct Struct_4_t *)(~(__int64)result);
            a1 = v7 + result;
            result = (struct Struct_4_t *)v7;
            result = (struct Struct_4_t *)((__int64)result - (__int64)a2);
            result -= 2;
            a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 3);
            if (!((a1 == 0))) {
                for (a2 = 0; a1 != a2; ++a2) {
                    a3 = v11[(__int64)a2];
                    a3->field_160 = dst4;
                    src2 = v8 + a2;
                    a3->field_3D0 = src2;
                }
                v8 += (__int64)a2;
            }
            if (result >= 3) {
                do {
                    result = *(dst4 + v8*8 + 984);
                    result->field_160 = dst4;
                    result->field_3D0 = v8;
                    result = *(dst4 + v8*8 + 992);
                    result->field_160 = dst4;
                    a1 = v8 + 1;
                    result->field_3D0 = a1;
                    result = *(dst4 + v8*8 + 1000);
                    result->field_160 = dst4;
                    a1 = v8 + 2;
                    result->field_3D0 = a1;
                    result = *(dst4 + v8*8 + 1008);
                    result->field_160 = dst4;
                    a1 = v8 + 3;
                    result->field_3D0 = a1;
                    v8 += 4;
                } while (v8 != v7);
            }
        }
        *(dst4 + 978) = *(dst4 + 978) - 1;
        dst4 = (__int64 *)arg_18;
        v10 = v_20;
        if (v_18 >= 2) {
            i = (__int64 *)arg_10;
            ++i;
            result = (struct Struct_4_t *)v10;
            v11 = *dst;
            result = (struct Struct_4_t *)((__int64)result - (__int64)v11);
            if (i != result) JUMPOUT(0x140043ed5);
            result = dst2 + 984;
            a1 = result + (__int64)(__int64)dst3*8;
            a2 = dst4 + 984;
            a3 =  + (__int64)(__int64)i*8;
            sub_1400F27F0(a1, a2, a3, src2);
            i = (__int64 *)((__int64)(__int64)i & 3);
            if (!((i == 0))) {
                a1 = dst2 + (__int64)(__int64)v11*8;
                a1 += 992;
                for (result = 0; i != result; ++result) {
                    a2 = ((__int64 *)a1)[(__int64)result];
                    a2->field_160 = dst2;
                    a3 = (__int64)result + (__int64)dst3;
                    a2->field_3D0 = a3;
                }
                dst3 = (__int64 *)((__int64)dst3 + (__int64)result);
            }
            if (arg_26 >= 3) {
                do {
                    result = *(dst2 + (__int64)(__int64)dst3*8 + 984);
                    result->field_160 = dst2;
                    result->field_3D0 = dst3;
                    result = *(dst2 + (__int64)(__int64)dst3*8 + 992);
                    result->field_160 = dst2;
                    a1 = dst3 + 1;
                    result->field_3D0 = a1;
                    result = *(dst2 + (__int64)(__int64)dst3*8 + 1000);
                    result->field_160 = dst2;
                    a1 = dst3 + 2;
                    result->field_3D0 = a1;
                    result = *(dst2 + (__int64)(__int64)dst3*8 + 1008);
                    result->field_160 = dst2;
                    a1 = dst3 + 3;
                    result->field_3D0 = a1;
                    dst3 += 4;
                } while (a1 != v10);
            }
        }
        off_140108030(a1, a2, a3);
        off_140108038(result, 0, dst4);
        result = (struct Struct_4_t *)dst2;
        a2 = (struct Struct_2_t *)src;
        return (__int64)a2;
    }
    return (__int64)result;
}