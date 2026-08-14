// inferred from 7 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    char field_8; // offset 8
    char field_9; // offset 9
    int field_A; // offset 10
    __int16 field_E; // offset 14
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

// inferred from 8 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[8];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    char _pad_40[8];
    __int64 field_50; // offset 80
    __int64 field_58; // offset 88
};

__int64 sub_1400583C0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140121D14;
extern __int64 off_140121D24;

__int64 __fastcall sub_14004CFC0(int a1, int *a2) {
    __int64 rsp;
    int v_150;
    int v_157;
    int v_15f;
    int v_167;
    int v_2e0;
    int v_48;
    int v_49;
    int v_4a;
    int v_4e;
    int v_50;
    int v_58;
    int v_60;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 result;
    int v5;
    __int64 v6;
    __int64 v7;
    __int64 v8;
    __int64 v13;
    __int64 v11;
    __int64 v9;
    __int64 v2;
    __int64 v10;
    __int64 v12;
    __m128i xmm0;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_2e0, xmm6);
    ptr2 = (struct Struct_2_t *)a2;
    ptr = (struct Struct_1_t *)a1;
    a1 = rsp + 712;
    sub_1400583C0(a1);
    result = ptr2->field_0;
    a1 = result - 8;
    if (result >= 8) a2 = a1;
    a1 = &off_140121D14;
    switch ((__int64)a2) {
        case 1:
            a1 = result - 2;
            if (a1 >= 6) result = a1;
            return a1;
        case 7:
            v_48 = 2;
            v_50 = _mm_cvtsi128_si64(xmm6);
            result = v_48;
            a1 = v_49;
            a2 = (int *)v_4a;
            v5 = v_4e;
            v6 = v_50;
            v7 = v_58;
            ptr->field_18 = v7;
            v8 = v_60;
            ptr->field_20 = v8;
            ptr->field_8 = result;
            ptr->field_9 = a1;
            ptr->field_A = a2;
            ptr->field_E = v5;
            return v8;
        case 8:
            ptr->field_10 = v6;
            break;
        default:
            a1 = &off_140121D24;
            switch (result) {
                default:
                    result = ptr2->field_20;
                    v13 = ptr2->field_38;
                    v11 = ptr2->field_40;
                    v9 = ptr2->field_50;
                    v2 = ptr2->field_58;
                    v10 = 0x8000000000000003;
                    if (result != v10) {
                        if (result > 0) {
                            v12 = ptr2->field_28;
                            off_140108030(a1, 1);
                            off_140108038(result, 0, v12);
                        }
                    }
                    if (v13 != v10) {
                        if (v13 > 0) {
                            off_140108030();
                            off_140108038(result, 0, v11);
                        }
                    }
                    ptr2 += 8;
                    if (v9 != v10) {
                        if (v9 > 0) {
                            off_140108030();
                            off_140108038(result, 0, v2);
                        }
                    }
                    xmm0 = _mm_loadu_si128((__m128i *)ptr2);
                    _mm_storeu_si128((__m128i *)&v_157, xmm0);
                    result = ptr2->field_10;
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
    return result;
}