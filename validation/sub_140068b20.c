// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14004F470();
__int64 sub_1400685B0();
__int64 sub_1400F37A0();
extern __int64 off_140116BA8;
extern __int64 off_14011AF40;
extern __int64 off_1401162A8;
extern __int64 off_140116232;

__int64 __fastcall sub_140068B20(int *a1,struct Struct_1_t *a2, int a3) {
    __int64 rsp;
    int arg_8;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_88;
    int v_90;
    int v_a0;
    int v_a8;
    int v_b0;
    __int64 v4;
    __m128i xmm6;
    struct Struct_3_t *ptr2;
    __int64 result;
    struct Struct_2_t *ptr;
    __int64 v8;
    __int64 v11;
    __int64 *src;
    __m128i xmm0;
    __int64 v9;
    __int64 v5;
    struct Struct_4_t *ptr3;
    __int64 *src2;

    _mm_store_si128((__m128i *)&v_b0, xmm6);
    v4 = ((__int64 *)a2)[3];
    xmm6 = _mm_setzero_si128();
    ptr2 = 8;
    result = 1;
    if (v4 != 0) {
        ptr = ((__int64 *)a2)[2];
        a3 = ptr->field_0;
        a3 &= 223;
        if (a3 == 69) {
            v8 = v4;
            --v8;
            if (!((v8 == 0))) {
                result = ptr->field_1;
                v11 = v4 - 2;
                src = ptr + 2;
                ((__int64 *)a2)[2] = (__int64)(src);
                ((__int64 *)a2)[3] = (__int64)(v11);
                if (result != 43) {
                    if (result != 45) {
                        src = ptr + 1;
                        xmm0 = _mm_setzero_si128();
                        _mm_storeu_si128((__m128i *)&v_40, xmm0);
                        v_28 = 1;
                        v_30 = 0;
                        v_38 = 8;
                        ((__int64 *)a2)[2] = (__int64)(src);
                        ((__int64 *)a2)[3] = (__int64)(v8);
                        result = rsp + 40;
                        v11 = (__int64)a1;
                        v9 = (__int64)a2;
                        sub_14004F470(result, a2, a3);
                        a2 = (struct Struct_1_t *)v9;
                        a1 = (int *)v11;
                        v11 = v8;
                    }
                }
                v_28 = 0;
                v_38 = 0;
                v_40 = 95;
                v_48 = 2;
                result = &off_140116BA8;
                v_50 = result;
                v_58 = 5;
                if (v11 != 0) {
                    result = *src;
                    a3 = v11 - 1;
                    v5 = src + 1;
                    ((__int64 *)a2)[2] = (__int64)(v5);
                    ((__int64 *)a2)[3] = (__int64)(a3);
                    result += 208;
                    if (result >= 10) {
                        ((__int64 *)a2)[2] = (__int64)(src);
                        ((__int64 *)a2)[3] = (__int64)(v11);
                        result = 2;
                        a2 = 0;
                    } else {
                        ptr3 = (struct Struct_4_t *)a1;
                        v_90 = 0;
                        result = rsp + 40;
                        v_a0 = result;
                        v_a8 = 0;
                        a1 = rsp + 96;
                        result = rsp + 144;
                        ptr2 = (struct Struct_3_t *)a3;
                        sub_1400685B0(a1, result, a2, v5);
                        a1 = (int *)v_60;
                        if (a1 != 3) {
                            a2 = (struct Struct_1_t *)v_68;
                            ptr2 = (struct Struct_3_t *)v_70;
                            xmm6 = _mm_loadu_si128((__m128i *)&v_78);
                            a3 = v_88;
                            result = 2;
                            if (a1 != 1) result = a1;
                            a1 = (int *)ptr3;
                            *a1 = result;
                            arg_8 = (int)a2;
                            a1[2] = ptr2;
                            _mm_storeu_si128((__m128i *)(a1 + 24), xmm6);
                            a1[5] = a3;
                        } else {
                            result = ptr2->field_10;
                            a2 = (struct Struct_1_t *)result;
                            a2 = (struct Struct_1_t *)((__int64)a2 - (__int64)src);
                            if (a2 > v11) {
                                result = &off_14011AF40;
                                v_60 = result;
                                v_68 = 1;
                                v_70 = 8;
                                xmm0 = _mm_setzero_si128();
                                _mm_storeu_si128((__m128i *)&v_78, xmm0);
                                a2 = &off_1401162A8;
                                a1 = rsp + 96;
                                sub_1400F37A0(a1, a2, a3);
                            } else {
                                result -= (__int64)ptr;
                                v4 -= result;
                                if (!((v4 < 0))) {
                                    a2 = ptr + result;
                                    ptr2->field_10 = a2;
                                    ptr2->field_18 = v4;
                                    ptr3->field_8 = ptr;
                                    ptr3->field_10 = result;
                                    *(__int64 *)ptr3 = (__int64)(3);
                                    xmm6 = _mm_load_si128((__m128i *)&v_b0);
                                    return _mm_cvtsi128_si64(xmm6);
                                }
                            }
                            result = &off_14011AF40;
                            v_28 = result;
                            v_30 = 1;
                            v_38 = 8;
                            xmm0 = _mm_setzero_si128();
                            _mm_storeu_si128((__m128i *)&v_40, xmm0);
                            a2 = &off_1401162A8;
                            a1 = rsp + 40;
                            sub_1400F37A0(a1, a2);
                            src = (__int64 *)a2;
                            v4 = (__int64)a1;
                            ptr2 = a2->field_0;
                            src2 = a2->field_8;
                            v11 = *(src2 + 24);
                            a2 = &off_140116232;
                            ((__int64 (*)())v11)(ptr2, a2, 15);
                            ptr = 1;
                            if (result == 0) JUMPOUT(0x140068de8);
                            result = (__int64)ptr;
                            return result;
                        }
                        return result;
                    }
                    return result;
                }
                return result;
            }
            return result;
        }
    }
    return result;
}