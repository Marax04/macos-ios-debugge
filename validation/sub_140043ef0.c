// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    char _pad_18[8];
    __int64 field_28; // offset 40
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

// inferred from 8 accesses on `ptr2`
struct Struct_6_t {
    char _pad_start[48];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    char _pad_40[16];
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
    char _pad_70[858];
    __int64 field_3D2; // offset 978
};

// inferred from 3 accesses on `ptr3`
struct Struct_7_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F37D0();
__int64 sub_1400F27F0();
__int64 sub_1400F27F6();
__int64 sub_14002EDF0();
extern __int64 off_140114650;
extern __int64 off_140114688;
extern __int64 off_14011B42B;
extern __int64 off_1401146E0;
extern __int64 off_1401146A0;
extern __int64 off_1401146C8;

__int64 __fastcall sub_140043EF0(struct Struct_1_t *a1,struct Struct_2_t *a2,struct Struct_3_t *a3, int a4) {
    int arg_10;
    int arg_20;
    int arg_30;
    int arg_40;
    int arg_50;
    int arg_58;
    int arg_68;
    int arg_78;
    int arg_80;
    int arg_88;
    int arg_90;
    int v_10;
    int v_20;
    __int64 v_30;
    int v_40;
    int v_50;
    int v_60;
    int str;
    char *dst;
    __int64 *dst2;
    struct Struct_4_t *result;
    struct Struct_5_t *ptr;
    struct Struct_6_t *ptr2;
    __int64 *dst3;
    struct Struct_7_t *ptr3;
    __int64 v9;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v5;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v7;
    __int64 v6;

    dst2 = a1->field_18;
    a4 = *(dst2 + 978);
    result = a2 + a4;
    if (result >= 12) {
        a1 = &off_140114650;
        a3 = &off_140114688;
        sub_1400F37D0(a1, 50, a3, a4);
    } else {
        ptr = (struct Struct_5_t *)a1;
        ptr2 = a1->field_28;
        dst3 = ptr2->field_3D2;
        dst3 = (__int64 *)((__int64)dst3 - (__int64)a2);
        if (!((dst3 < 0))) {
            *(dst2 + 978) = result;
            ptr2->field_3D2 = dst3;
            ptr3 = (__int64)(__int64)a2 * 56;
            arg_88 = (int)a2;
            v9 = (__int64)a2;
            v9 <<= 5;
            xmm0 = _mm_loadu_si128((__m128i *)(ptr2 + v9 - 32));
            xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + v9 - 16));
            _mm_store_si128((__m128i *)&arg_10, xmm1);
            _mm_store_si128((__m128i *)&*dst, xmm0);
            result = ptr->field_0;
            a1 = ptr->field_10;
            v5 = (__int64)(__int64)a1 * 56;
            a3 = *(__int64 *)(result + v5 + 408);
            arg_50 = (int)a3;
            xmm0 = _mm_loadu_si128((__m128i *)(result + v5 + 360));
            xmm1 = _mm_loadu_si128((__m128i *)(result + v5 + 376));
            xmm2 = _mm_loadu_si128((__m128i *)(result + v5 + 392));
            _mm_store_si128((__m128i *)&arg_40, xmm2);
            _mm_store_si128((__m128i *)&arg_30, xmm1);
            _mm_store_si128((__m128i *)&arg_20, xmm0);
            a3 = *(__int64 *)((__int64)ptr2 + (__int64)ptr3 + 352);
            xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)ptr3 + 304));
            xmm1 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)ptr3 + 320));
            xmm2 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)ptr3 + 336));
            *(__int64 *)(result + v5 + 408) = (__int64)(a3);
            a2 = ptr2 + 360;
            arg_78 = (int)a2;
            _mm_storeu_si128((__m128i *)(result + v5 + 360), xmm0);
            _mm_storeu_si128((__m128i *)(result + v5 + 392), xmm2);
            _mm_storeu_si128((__m128i *)(result + v5 + 376), xmm1);
            a3 = ptr3 - 56;
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
            a1 = a4 * 56;
            *(__int64 *)((__int64)dst2 + (__int64)a1 + 408) = result;
            _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)a1 + 392), xmm2);
            _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)a1 + 376), xmm1);
            _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)a1 + 360), xmm0);
            result = (struct Struct_4_t *)a4;
            result = (struct Struct_4_t *)((__int64)(__int64)result << 5);
            xmm0 = _mm_load_si128((__m128i *)&v_20);
            xmm1 = _mm_load_si128((__m128i *)&v_10);
            _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result + 16), xmm1);
            _mm_storeu_si128((__m128i *)((__int64)dst2 + (__int64)result), xmm0);
            arg_80 = a4;
            v7 = a4 + 1;
            a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst2);
            a1 += 416;
            sub_1400F27F0(a1, a2, a3, a4);
            arg_90 = v7;
            a1 = (struct Struct_1_t *)v7;
            a1 = (struct Struct_1_t *)((__int64)(__int64)a1 << 5);
            a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst2);
            a3 = v9 - 32;
            sub_1400F27F0(a1, ptr2, a3);
            a2 = (__int64)ptr2 + (__int64)ptr3;
            a2 += 360;
            a3 = (__int64)(__int64)dst3 * 56;
            a1 = (struct Struct_1_t *)arg_78;
            sub_1400F27F6(a1, a2, a3);
            v9 += (__int64)ptr2;
            a3 = (struct Struct_3_t *)dst3;
            a3 = (struct Struct_3_t *)((__int64)(__int64)a3 << 5);
            sub_1400F27F6(ptr2, v9, a3);
            result = ptr->field_30;
            if (ptr->field_20 == 0) {
                if (result != 0) {
                    a1 = &off_14011B42B;
                    a3 = &off_1401146E0;
                    sub_1400F37D0(a1, 40, a3);
                    a2 = (struct Struct_2_t *)((__int64)(__int64)a2 & -4);
                    a1 = 0;
                    do {
                        a3 = *(__int64 *)(ptr2 + (__int64)(__int64)a1*8 + 984);
                        a3->field_160 = ptr2;
                        a4 = (int)a1;
                        a3->field_3D0 = a1;
                        a3 = *(__int64 *)(ptr2 + (__int64)(__int64)a1*8 + 992);
                        a3->field_160 = ptr2;
                        v5 = a4 + 1;
                        a3->field_3D0 = v5;
                        a3 = *(__int64 *)(ptr2 + (__int64)(__int64)a1*8 + 1000);
                        a3->field_160 = ptr2;
                        v5 = a4 + 2;
                        a3->field_3D0 = v5;
                        a3 = *(__int64 *)(ptr2 + (__int64)(__int64)a1*8 + 1008);
                        a1 += 4;
                        a3->field_160 = ptr2;
                        a4 += 3;
                        a3->field_3D0 = a4;
                    } while (a1 != a2);
                    if (result != 0) {
                        do {
                            a2 = *(__int64 *)(ptr2 + (__int64)(__int64)a1*8 + 984);
                            a2->field_160 = ptr2;
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
                    ptr = ptr2 + 984;
                    v9 = arg_90;
                    a1 =  + v9*8 + 984;
                    a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst2);
                    ptr3 = (struct Struct_7_t *)arg_88;
                    a3 =  + (__int64)(__int64)ptr3*8;
                    sub_1400F27F0(a1, ptr, a3);
                    a2 = ptr2 + (__int64)(__int64)ptr3*8;
                    a2 += 984;
                    a3 =  + (__int64)(__int64)dst3*8 + 8;
                    sub_1400F27F6(ptr, a2, a3);
                    a2 = (struct Struct_2_t *)arg_80;
                    result = *(dst2 + (__int64)(__int64)a2*8 + 992);
                    result->field_160 = dst2;
                    result->field_3D0 = v9;
                    if (ptr3 != 1) {
                        result = *(dst2 + (__int64)(__int64)a2*8 + 1000);
                        result->field_160 = dst2;
                        a1 = a2 + 2;
                        result->field_3D0 = a1;
                        if (ptr3 != 2) {
                            result = *(dst2 + (__int64)(__int64)a2*8 + 1008);
                            result->field_160 = dst2;
                            a1 = a2 + 3;
                            result->field_3D0 = a1;
                            if (ptr3 != 3) {
                                result = *(dst2 + (__int64)(__int64)a2*8 + 1016);
                                result->field_160 = dst2;
                                a1 = a2 + 4;
                                result->field_3D0 = a1;
                                if (ptr3 != 4) {
                                    result = *(dst2 + (__int64)(__int64)a2*8 + 0x400);
                                    result->field_160 = dst2;
                                    a1 = a2 + 5;
                                    result->field_3D0 = a1;
                                }
                            }
                        }
                    }
                    a2 = dst3 + 1;
                    result = (struct Struct_4_t *)a2;
                    result = (struct Struct_4_t *)((__int64)(__int64)result & 3);
                    if (dst3 >= 3) {
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
    a1 = &off_1401146A0;
    a3 = &off_1401146C8;
    sub_1400F37D0(a1, 40, a3);
    *dst = -2;
    ptr3 = (struct Struct_7_t *)a2;
    ptr2 = (struct Struct_6_t *)a1;
    sub_14002EDF0(0, 984);
    if (result == 0) JUMPOUT(0x1400444a9);
    dst2 = (__int64 *)result;
    result->field_160 = 0;
    dst3 = ptr3->field_0;
    v6 = ptr3->field_10;
    result = *(dst3 + 978);
    ptr = (struct Struct_5_t *)v6;
    ptr = (struct Struct_5_t *)(~(__int64)ptr);
    ptr = (struct Struct_5_t *)((__int64)ptr + (__int64)result);
    *(dst2 + 978) = ptr;
    result = v6 * 56;
    a1 = *(__int64 *)((__int64)dst3 + (__int64)result + 408);
    v_20 = (int)a1;
    xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 360));
    xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 376));
    xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 392));
    _mm_store_si128((__m128i *)&v_30, xmm2);
    _mm_store_si128((__m128i *)&v_40, xmm1);
    _mm_store_si128((__m128i *)&v_50, xmm0);
    result = (struct Struct_4_t *)v6;
    result = (struct Struct_4_t *)((__int64)(__int64)result << 5);
    a1 = *(__int64 *)((__int64)dst3 + (__int64)result);
    a2 = *(__int64 *)((__int64)dst3 + (__int64)result + 8);
    xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)result + 16));
    _mm_store_si128((__m128i *)&v_60, xmm0);
    str = (int)a2;
    v_10 = (int)a1;
    if (ptr >= 12) JUMPOUT(0x1400444b8);
    result = dst3 + 360;
    v9 = v6 + 1;
    a1 = (struct Struct_1_t *)dst2;
    a1 += 360;
    a2 = v9 * 56;
    a2 = (struct Struct_2_t *)((__int64)a2 + (__int64)result);
    a3 = (__int64)(__int64)ptr * 56;
    sub_1400F27F0(a1, a2, a3);
    v9 <<= 5;
    v9 += (__int64)dst3;
    ptr = (struct Struct_5_t *)((__int64)(__int64)ptr << 5);
    sub_1400F27F0(dst2, v9, ptr);
    *(dst3 + 978) = v7;
    xmm0 = _mm_load_si128((__m128i *)&v_50);
    xmm1 = _mm_load_si128((__m128i *)&v_40);
    xmm2 = _mm_load_si128((__m128i *)&v_30);
    _mm_storeu_si128((__m128i *)ptr2, xmm0);
    _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
    _mm_storeu_si128((__m128i *)(ptr2 + 32), xmm2);
    result = (struct Struct_4_t *)v_20;
    ptr2->field_30 = result;
    xmm0 = _mm_load_si128((__m128i *)&v_60);
    _mm_storeu_si128((__m128i *)(ptr2 + 72), xmm0);
    result = ptr3->field_8;
    ptr2->field_58 = dst3;
    ptr2->field_60 = result;
    result = (struct Struct_4_t *)v_10;
    ptr2->field_38 = result;
    result = (struct Struct_4_t *)str;
    ptr2->field_40 = result;
    ptr2->field_68 = dst2;
    ptr2->field_70 = 0;
    return (__int64)result;
}