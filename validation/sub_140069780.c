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

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_140054AA0();
__int64 sub_14004F470();
__int64 sub_140055430();
extern __int64 off_14011AB0E;

__int64 __fastcall sub_140069780(int *a1, int *a2) {
    __int64 rsp;
    int arg_1;
    int arg_10;
    int arg_18;
    int v_100;
    int v_108;
    int v_110;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_48;
    int v_50;
    int v_70;
    int v_78;
    int v_90;
    int v_98;
    int v_a0;
    int v_a8;
    int v_c8;
    int v_d8;
    int v_e0;
    int v_e8;
    int v_f0;
    char *str;
    struct Struct_1_t *ptr;
    __int64 v4;
    struct Struct_2_t *ptr2;
    __int64 v6;
    struct Struct_3_t *ptr3;
    __m128i xmm0;
    __int64 v1;
    __int64 v5;
    __m128i xmm6;
    __int64 v9;
    __int64 v10;
    __int64 v8;

    _mm_store_si128((__m128i *)&v_110, xmm6);
    ptr = (struct Struct_1_t *)a1;
    v4 = arg_18;
    if (v4 != 0) {
        ptr2 = (struct Struct_2_t *)a2;
        a1 = (int *)arg_10;
        a2 = *a1;
        v6 = v4 - 1;
        ptr3 = a1 + 1;
        ptr2->field_10 = ptr3;
        ptr2->field_18 = v6;
        if (a2 != 10) {
            if (a2 == 13) {
                if (v6 != 0) {
                    if (arg_1 != 10) {
                        xmm0 = _mm_setzero_si128();
                        _mm_store_si128((__m128i *)&v_20, xmm0);
                        v1 = 1;
                    } else {
                        v4 -= 2;
                        a1 += 2;
                        ptr3 = (struct Struct_3_t *)a1;
                        v6 = v4;
                        v_c8 = 0;
                        v_d8 = 0;
                        v5 = &off_14011AB0E;
                        v_e0 = v5;
                        v_e8 = 1;
                        v_f0 = 0;
                        v_100 = 1;
                        v_108 = 0x920;
                        xmm6 = _mm_setzero_si128();
                        if (v6 == 0) {
                            v4 = rsp + 176;
                            _mm_storeu_si128((__m128i *)v4, xmm6);
                            v_98 = 1;
                            v_a0 = 0;
                            v_a8 = 8;
                            ptr2->field_10 = ptr3;
                            ptr2->field_18 = v6;
                            a1 = rsp + 104;
                            a2 = rsp + 240;
                            sub_140054AA0(a1, a2, ptr2);
                            v1 = (__int64)str;
                            while (v1 != 1) {
                                v9 = v_70;
                                v10 = v_78;
                                v4 = rsp + 128;
                                xmm0 = _mm_loadu_si128((__m128i *)v4);
                                _mm_store_si128((__m128i *)&v_50, xmm0);
                                v8 = v_90;
                                a1 = rsp + 152;
                                sub_14004F470(a1);
                                if (v1 == 3) {
                                    v4 = ptr2->field_18;
                                    while (v4 != v6) {
                                        ptr3 = ptr2->field_10;
                                        v6 = v4;
                                        if (v4 != 0) {
                                            a1 = ptr3->field_0;
                                            v4 = v6 - 1;
                                            a2 = ptr3 + 1;
                                            ptr2->field_10 = a2;
                                            ptr2->field_18 = v4;
                                            a1 = ptr3->field_1;
                                            v4 = v6 - 2;
                                            a2 = ptr3 + 2;
                                            ptr2->field_10 = a2;
                                            ptr2->field_18 = v4;
                                        }
                                    }
                                    xmm0 = _mm_setzero_si128();
                                    _mm_store_si128((__m128i *)&v_20, xmm0);
                                    v1 = 2;
                                    v10 = 8;
                                    v9 = 0;
                                    *(__int64 *)ptr = (__int64)(v1);
                                    ptr->field_8 = v9;
                                    ptr->field_10 = v10;
                                    xmm0 = _mm_load_si128((__m128i *)&v_20);
                                    _mm_storeu_si128((__m128i *)(ptr + 24), xmm0);
                                    ptr->field_28 = v8;
                                    xmm6 = _mm_load_si128((__m128i *)&v_110);
                                    return _mm_cvtsi128_si64(xmm6);
                                }
                                if (v1 != 1) JUMPOUT(0x140069a33);
                                v_20 = 1;
                                v_28 = v9;
                                v_30 = v10;
                                xmm0 = _mm_load_si128((__m128i *)&v_50);
                                _mm_storeu_si128((__m128i *)&v_38, xmm0);
                                v_48 = v8;
                                ptr2->field_10 = ptr3;
                                ptr2->field_18 = v6;
                                a1 = rsp + 32;
                                sub_14004F470(a1);
                                *(__int64 *)ptr = (__int64)(3);
                                return (__int64)a1;
                            }
                            a1 = rsp + 32;
                            a2 = rsp + 152;
                            sub_140055430(a1, a2, str);
                            v1 = v_20;
                            v9 = v_28;
                            v10 = v_30;
                            xmm0 = _mm_loadu_si128((__m128i *)&v_38);
                            _mm_store_si128((__m128i *)&v_50, xmm0);
                            v8 = v_48;
                            return v8;
                        }
                        return v8;
                    }
                    return v8;
                }
            }
            return v8;
        }
        return v8;
    }
    return v8;
}