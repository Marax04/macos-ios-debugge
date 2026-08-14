// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140018820();
__int64 sub_140033250();
__int64 sub_1400127C0();
__int64 sub_140035F7E();
extern __int64 off_140121B8C;
extern __int64 off_140115F00;
extern __int64 off_14010B438;
extern __int64 off_140118AEA;
extern __int64 off_140117BCE;
extern __int64 off_14010B408;
extern __int64 off_14010B400;
extern __int64 off_140116F20;
extern __int64 off_140115F2E;
extern __int64 off_140110A3A;

__int64 __fastcall sub_140035660(int *a1, int *a2) {
    int arg_18;
    int v_20;
    int v_30;
    int v_50;
    int v_8;
    int *v_0;
    char *str;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 result;
    __int64 v5;
    int v2;
    __m128i xmm0;
    __int64 v7;
    __int64 v8;
    __int64 v6;

    v_8 = -2;
    ptr = (struct Struct_1_t *)a2;
    ptr2 = *a1;
    result = (__int64)ptr2;
    result &= 3;
    a1 = &off_140121B8C;
    result = v_0[result];
    result += (__int64)a1;
    JUMPOUT(result);
    a1 = ptr->field_0;
    result = ptr->field_8;
    a2 = &off_140115F00;
    v5 = 5;
    ((__int64 (*)())(arg_18))();
    v2 = 1;
    if (result == 0) {
        if ((ptr->field_12 & 128) != 0) {
            a1 = ptr->field_0;
            result = ptr->field_8;
            a2 = &off_14010B438;
            v5 = 3;
            ((__int64 (*)())(arg_18))();
            if (result == 0) {
                v_50 = 1;
                xmm0 = _mm_loadu_si128((__m128i *)ptr);
                _mm_store_si128((__m128i *)&v_30, xmm0);
                result = str - 80;
                v_20 = result;
                a2 = &off_140118AEA;
                a1 = str - 48;
                sub_140018820(a1, a2, 4);
                if (result == 0) {
                    a2 = &off_140117BCE;
                    a1 = str - 48;
                    sub_140018820(a1, a2, 2);
                    if (result == 0) {
                        a1 = ptr2->field_10;
                        v7 = &off_14010B408;
                        a2 = str - 48;
                        sub_140033250(a1, a2, v7);
                        if (result == 0) {
                            a2 = &off_14010B400;
                            a1 = str - 48;
                            sub_140018820(a1, a2, 2);
                            if (result == 0) {
                                if ((ptr->field_12 & 128) != 0) JUMPOUT(0x140035e60);
                                a1 = ptr->field_0;
                                result = ptr->field_8;
                                a2 = &off_140116F20;
                                v5 = 2;
                                ((__int64 (*)())(arg_18))();
                                if (result == 0) {
                                    a1 = ptr->field_0;
                                    result = ptr->field_8;
                                    a2 = &off_140115F2E;
                                    v5 = 7;
                                    ((__int64 (*)())(arg_18))();
                                    if (result == 0) {
                                        a1 = ptr->field_0;
                                        result = ptr->field_8;
                                        a2 = &off_140117BCE;
                                        v5 = 2;
                                        ((__int64 (*)())(arg_18))();
                                        if (result == 0) {
                                            a1 = ptr2->field_0;
                                            a2 = ptr2->field_8;
                                            v8 = ptr->field_0;
                                            v6 = ptr->field_8;
                                            sub_1400127C0(a1, a2, v8, v6);
                                            return sub_140035F7E();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            a1 = ptr->field_0;
            result = ptr->field_8;
            a2 = &off_140110A3A;
            v5 = 3;
            ((__int64 (*)())(arg_18))();
            if (result == 0) {
                a1 = ptr->field_0;
                result = ptr->field_8;
                a2 = &off_140118AEA;
                v5 = 4;
                ((__int64 (*)())(arg_18))();
                if (result == 0) {
                    a1 = ptr->field_0;
                    result = ptr->field_8;
                    a2 = &off_140117BCE;
                    v5 = 2;
                    ((__int64 (*)())(arg_18))();
                    if (result == 0) {
                        a1 = ptr2->field_10;
                        a2 = ptr->field_0;
                        v5 = ptr->field_8;
                        sub_140033250(a1, a2, v5);
                        return v5;
                    }
                }
            }
        }
    }
    result = v2;
    return result;
}