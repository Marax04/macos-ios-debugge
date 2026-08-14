// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char field_8; // offset 8
    __int64 field_9; // offset 9
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int16 field_10; // offset 16
    __int64 field_12; // offset 18
};

extern __int64 off_14011AB0E;
extern __int64 off_14010B408;
extern __int64 off_14010B400;
extern __int64 off_140116F20;

__int64 __fastcall sub_140018D00(int *a1, __int64 a2, int a3) {
    int arg_18;
    int v_1;
    int v_10;
    int v_18;
    int v_20;
    int v_30;
    int v_40;
    char *str;
    struct Struct_1_t *ptr;
    __int64 result;
    struct Struct_2_t *ptr2;
    __int64 *v5;
    __int64 v2;
    __int64 v6;
    __m128i xmm0;
    __int64 v7;

    ptr = (struct Struct_1_t *)a1;
    result = 1;
    if (*(a1 + 8) == 0) {
        ptr2 = ptr->field_0;
        result = ptr->field_9;
        if ((ptr2->field_12 & 128) != 0) {
            if (result == 0) {
                a1 = ptr2->field_0;
                v5 = ptr2->field_8;
                result = &off_14011AB0E;
                v2 = a3;
                a3 = 1;
                v6 = a2;
                a2 = result;
                ((__int64 (*)())(*(v5 + 24)))();
                a2 = v6;
                a1 = (int *)result;
                result = 1;
                if (a1 == 0) {
                    v_1 = 1;
                    xmm0 = _mm_loadu_si128((__m128i *)ptr2);
                    _mm_store_si128((__m128i *)&v_40, xmm0);
                    result = str - 1;
                    v_30 = result;
                    result = ptr2->field_10;
                    v_10 = result;
                    result = str - 64;
                    v_20 = result;
                    result = &off_14010B408;
                    v_18 = result;
                    result = str - 32;
                    ((__int64 (*)())a3)(a2, result, v2, v5);
                    if (result == 0) {
                        a1 = (int *)v_20;
                        result = v_18;
                        a2 = &off_14010B400;
                        a3 = 2;
                        ((__int64 (*)())(arg_18))();
                    } else {
                        result = 1;
                    }
                }
                ptr->field_8 = result;
                ptr->field_9 = 1;
                result = (__int64)ptr;
                return result;
            }
            return result;
        } else {
            if (result != 0) {
                a1 = ptr2->field_0;
                v5 = ptr2->field_8;
                result = &off_140116F20;
                v2 = a3;
                a3 = 2;
                v7 = a2;
                a2 = result;
                ((__int64 (*)())(*(v5 + 24)))();
                a2 = v7;
                a1 = (int *)result;
                result = 1;
                if (a1 == 0) {
                    ((__int64 (*)())a3)(a2, ptr2, v2, v5);
                }
                return result;
            }
            return result;
        }
    }
    return result;
}