// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 9 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    char field_8; // offset 8
    char field_9; // offset 9
    int field_A; // offset 10
    __int16 field_E; // offset 14
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

// inferred from 9 accesses on `ptr3`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[8];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    __int64 field_48; // offset 72
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
};

__int64 sub_1400F37A0();
__int64 sub_1400583C0();
__int64 sub_1400F27F0();
__int64 sub_14004CFC0();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F8440();
__int64 sub_1400F27F6();
__int64 sub_140046190();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401151E8;
extern __int64 off_140115260;
extern __int64 off_140121D14;
extern __int64 off_140121D24;

__int64 __fastcall sub_14004CD40(int *a1, int *a2) {
    __int64 rsp;
    int v_150;
    int v_157;
    int v_15f;
    int v_167;
    int v_190;
    int v_20;
    int v_28;
    int v_2e0;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_49;
    int v_4a;
    int v_4e;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_d0;
    int v_e0;
    __int64 result;
    __m128i xmm0;
    struct Struct_3_t *ptr3;
    struct Struct_2_t *ptr2;
    __int64 v5;
    __int64 v6;
    __int64 v7;
    __int64 v8;
    __int64 v13;
    struct Struct_1_t *ptr;
    __int64 i;
    __int64 v2;
    __int64 v10;
    __int64 v12;
    __m128i xmm6;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;

    _mm_store_si128((__m128i *)&v_190, xmm6);
    result = a2[21];
    a2[21] = 12;
    if (result == 12) {
        result = &off_1401151E8;
        v_20 = result;
        v_28 = 1;
        v_30 = 8;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_38, xmm0);
        a2 = &off_140115260;
        a1 = rsp + 32;
        sub_1400F37A0(a1, a2);
        _mm_store_si128((__m128i *)&v_2e0, xmm6);
        ptr3 = (struct Struct_3_t *)a2;
        ptr2 = (struct Struct_2_t *)a1;
        a1 = rsp + 712;
        sub_1400583C0(a1);
        result = ptr3->field_0;
        a1 = result - 8;
        if (result >= 8) a2 = a1;
        a1 = &off_140121D14;
        switch ((__int64)a2) {
            case 1:
                a1 = result - 2;
                /* cmp result , 2 */;
                if (a1 >= 6) result = a1;
                return (__int64)a1;
            case 7:
                v_48 = 2;
                v_50 = _mm_cvtsi128_si64(xmm6);
                result = v_48;
                a1 = (int *)v_49;
                a2 = (int *)v_4a;
                v5 = v_4e;
                v6 = v_50;
                v7 = v_58;
                ptr2->field_18 = v7;
                v8 = v_60;
                ptr2->field_20 = v8;
                ptr2->field_8 = result;
                ptr2->field_9 = a1;
                ptr2->field_A = a2;
                ptr2->field_E = v5;
                return v8;
            case 8:
                ptr2->field_10 = v6;
                break;
            default:
                a1 = &off_140121D24;
                switch (result) {
                    default:
                        result = ptr3->field_20;
                        v13 = ptr3->field_38;
                        ptr = ptr3->field_40;
                        i = ptr3->field_50;
                        v2 = ptr3->field_58;
                        v10 = 0x8000000000000003;
                        if (result != v10) {
                            if (result > 0) {
                                v12 = ptr3->field_28;
                                off_140108030(a1, 1);
                                off_140108038(result, 0, v12);
                            }
                        }
                        if (v13 != v10) {
                            if (v13 > 0) {
                                off_140108030();
                                off_140108038(result, 0, ptr);
                            }
                        }
                        ptr3 += 8;
                        if (i != v10) {
                            if (i > 0) {
                                off_140108030();
                                off_140108038(result, 0, v2);
                            }
                        }
                        xmm0 = _mm_loadu_si128((__m128i *)ptr3);
                        _mm_storeu_si128((__m128i *)&v_157, xmm0);
                        result = ptr3->field_10;
                        v_167 = result;
                        v_48 = 0;
                        xmm0 = _mm_loadu_si128((__m128i *)&v_150);
                        _mm_storeu_si128((__m128i *)&v_49, xmm0);
                        result = v_15f;
                        v_58 = result;
                        result = v_167;
                        v_60 = result;
                        break;
                }
                return v_60;
        }
        return v_60;
    } else {
        ptr2 = (struct Struct_2_t *)a2;
        ptr3 = (struct Struct_3_t *)a1;
        a2 += 176;
        ptr = ptr2->field_20;
        v2 = ptr2->field_28;
        v12 = ptr2->field_30;
        xmm6 = _mm_loadu_si128((__m128i *)(ptr2 + 56));
        v_e0 = result;
        a1 = rsp + 232;
        sub_1400F27F0(a1, a2, 168);
        a1 = rsp + 32;
        a2 = rsp + 224;
        sub_1400583C0(a1, a2);
        if (v_20 != 1) {
            result = 0x8000000000000003;
            if (v12 != result) {
                result = 0x8000000000000002;
                if (v12 >= result) {
                    i = 1;
                } else {
                    i = 0;
                }
                v12 = rsp + 32;
                a2 = rsp + 224;
                sub_1400F27F0(v12, a2, 176);
                v_d0 = 0;
                sub_14004CFC0(ptr3, v12);
                if (ptr3->field_0 != 2) {
                    xmm0 = _mm_loadu_si128((__m128i *)ptr3);
                    xmm1 = _mm_loadu_si128((__m128i *)(ptr3 + 16));
                    xmm2 = _mm_loadu_si128((__m128i *)(ptr3 + 32));
                    xmm3 = _mm_loadu_si128((__m128i *)(ptr3 + 48));
                    _mm_store_si128((__m128i *)&v_20, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)(ptr3 + 80));
                    _mm_store_si128((__m128i *)&v_70, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)(ptr3 + 64));
                    _mm_store_si128((__m128i *)&v_60, xmm0);
                    _mm_store_si128((__m128i *)&v_50, xmm3);
                    _mm_store_si128((__m128i *)&v_40, xmm2);
                    _mm_store_si128((__m128i *)&v_30, xmm1);
                    if ((v_20 & 1) == 0) {
                        v_20 = i;
                        _mm_storeu_si128((__m128i *)&v_28, xmm6);
                    }
                    if (v2 < 0) {
                        sub_1400F3360();
                    }
                    if (!((0 /* unresolved: flags == */))) {
                        sub_14002EDF0(0, v2);
                        v12 = result;
                        if (result == 0) {
                            sub_1400F3326(1, v2);
                            v12 = 1;
                        }
                        sub_1400F27F0(v12, ptr, v2);
                        i = v_60;
                        if (i == v_50) {
                            a1 = rsp + 80;
                            sub_1400F8440(a1);
                            ptr = (struct Struct_1_t *)v_58;
                            if (i != 0) {
                                a1 = ptr + 24;
                                result =  + i*8;
                                v5 = result + result*2;
                                sub_1400F27F6(a1, ptr, v5);
                            } else {
                            }
                            *(__int64 *)ptr = (__int64)(v2);
                            ptr->field_8 = v12;
                            ptr->field_10 = v2;
                            ++i;
                            v_60 = i;
                            xmm0 = _mm_load_si128((__m128i *)&v_70);
                            _mm_storeu_si128((__m128i *)(ptr3 + 80), xmm0);
                            xmm0 = _mm_load_si128((__m128i *)&v_20);
                            xmm1 = _mm_load_si128((__m128i *)&v_30);
                            xmm2 = _mm_load_si128((__m128i *)&v_40);
                            xmm3 = _mm_load_si128((__m128i *)&v_50);
                            _mm_storeu_si128((__m128i *)(ptr3 + 48), xmm3);
                            _mm_storeu_si128((__m128i *)(ptr3 + 32), xmm2);
                            _mm_storeu_si128((__m128i *)(ptr3 + 16), xmm1);
                            _mm_storeu_si128((__m128i *)ptr3, xmm0);
                            result = v_60;
                            ptr3->field_40 = result;
                            result = v_68;
                            ptr3->field_48 = result;
                            ptr2 += 24;
                            sub_140046190(ptr2);
                            xmm6 = _mm_load_si128((__m128i *)&v_190);
                            return _mm_cvtsi128_si64(xmm6);
                        } else {
                            ptr = (struct Struct_1_t *)v_58;
                            if (i != 0) {
                                return (__int64)ptr;
                            }
                            return (__int64)ptr;
                        }
                        return (__int64)ptr;
                    }
                    return (__int64)ptr;
                }
                return (__int64)ptr;
            }
            return (__int64)ptr;
        } else {
            i = 1;
            xmm6 = _mm_loadu_si128((__m128i *)&v_28);
        }
        return result;
    }
}