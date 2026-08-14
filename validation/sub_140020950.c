// inferred from 2 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 5 accesses on `ptr2`
struct Struct_3_t {
    int field_0; // offset 0
    char field_4; // offset 4
    char field_5; // offset 5
    char field_6; // offset 6
    __int64 field_7; // offset 7
};

// inferred from 3 accesses on `ptr3`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr4`
struct Struct_5_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F35E0();
__int64 sub_140038A70();
__int64 sub_140020D81();
__int64 sub_14001D4E0();
__int64 sub_14000ECF0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140110698;
extern __int64 off_14012D268;
extern __int64 off_140108260;
extern __int64 off_140108060;
extern __int64 off_140121108;
extern __int64 off_14012D270;
extern __int64 off_14012D180;

__int64 __fastcall sub_140020950(__int64 *a1) {
    __int64 rsp;
    __int64 arg_8;
    int v_20;
    __int64 v_28;
    int v_30;
    int v_40;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_8a;
    int v_8e;
    int v_90;
    int v_98;
    int v_a0;
    int v_b0;
    int v_c0;
    __int64 v_d0;
    __int64 v_d8;
    __int64 v_e0;
    __int64 v_e8;
    __int64 v_ea;
    __int64 v_ee;
    __int64 *v_0;
    struct Struct_1_t *result;
    __int64 *dst;
    struct Struct_3_t *ptr2;
    __int64 *src;
    __int64 *src2;
    __int64 v7;
    int v12;
    __int64 v9;
    struct Struct_2_t *ptr;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v3;
    struct Struct_4_t *ptr3;
    struct Struct_5_t *ptr4;

    result = *a1;
    dst = result->field_0;
    *(__int64 *)result = (__int64)(0);
    if (dst == 0) {
        a1 = &off_140110698;
        sub_1400F35E0(a1);
        sub_140038A70();
        ptr2 = (struct Struct_3_t *)a1;
        src = a1 + 4;
        a1 = 1;
        result = 0;
        /* cmpxchg %(__int64)a1, 4(%(__int64)ptr2) */;
        if ((0 /* unresolved: flags != */)) JUMPOUT(0x140020db3);
        result = off_14012D268;
        result = (struct Struct_1_t *)((__int64)(__int64)result << 1);
        if (result != 0) JUMPOUT(0x140020dce);
        src2 = 0;
        result = ptr2->field_5;
        if (result != 0) JUMPOUT(0x140020de4);
        dst = rsp + 40;
        v7 = off_140108260;
        v12 = 1;
        v9 = off_140108060;
        do {
            if (ptr2->field_6 != 0) JUMPOUT(0x140020d49);
            ptr = ptr2->field_0;
            result = 0;
            { __int64 __xchg_tmp = ptr2->field_4; ptr2->field_4 = result; result = __xchg_tmp; };
            if (result == 2) JUMPOUT(0x140020d3e);
            v_28 = (__int64)ptr;
            ((__int64 (*)())v7)(ptr2, dst, 4, 0xFFFFFFFF);
            if (result != 1) JUMPOUT(0x140020d20);
            result = 0;
            /* cmpxchg %v12, (%(__int64)src) */;
            if ((0 /* unresolved: flags != */)) JUMPOUT(0x140020d2c);
            result = ptr2->field_5;
        } while (result == 0);
        return sub_140020D81();
    } else {
        v_88 = 0;
        v_58 = 0;
        v_30 = 0;
        v_68 = 0;
        v_78 = 0;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_40, xmm0);
        result = (struct Struct_1_t *)v_80;
        v_e0 = (__int64)result;
        result = (struct Struct_1_t *)v_88;
        v_e8 = (__int64)result;
        result = (struct Struct_1_t *)v_8a;
        v_ea = (__int64)result;
        result = (struct Struct_1_t *)v_8e;
        v_ee = (__int64)result;
        result = (struct Struct_1_t *)v_70;
        v_d0 = (__int64)result;
        result = (struct Struct_1_t *)v_78;
        v_d8 = (__int64)result;
        xmm1 = _mm_loadu_si128((__m128i *)&v_60);
        _mm_store_si128((__m128i *)&v_c0, xmm1);
        xmm1 = _mm_loadu_si128((__m128i *)&v_50);
        _mm_store_si128((__m128i *)&v_b0, xmm1);
        _mm_store_si128((__m128i *)&v_a0, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_30);
        _mm_store_si128((__m128i *)&v_90, xmm0);
        a1 = rsp + 32;
        v3 = rsp + 144;
        sub_14001D4E0(a1, v3);
        ptr = (struct Struct_2_t *)v_20;
        src = (__int64 *)v_28;
        if (ptr == 3) {
            src2 = src;
        } else {
            if (ptr == 2) {
                ptr2 = (struct Struct_3_t *)src;
                ptr2 = (struct Struct_3_t *)((__int64)(__int64)ptr2 & 3);
                result = &off_140121108;
                switch ((__int64)ptr2) {
                    default:
                        result = (struct Struct_1_t *)src;
                        result = (struct Struct_1_t *)((__int64)(__int64)result >> 32);
                        if (result == 120) {
                            result = off_14012D270;
                            a1 = __readgsqword(88);
                            result = v_0[(__int64)result];
                            if (result->field_18 == 0) {
                                v_40 = 1;
                                v_88 = 1;
                                a1 = rsp + 144;
                                v3 = rsp + 48;
                                sub_14001D4E0(a1, v3);
                                result = (struct Struct_1_t *)v_90;
                                if (result != 3) {
                                    if (result >= 2) {
                                        ptr2 = (struct Struct_3_t *)v_98;
                                        result = (struct Struct_1_t *)ptr2;
                                        result = (struct Struct_1_t *)((__int64)(__int64)result & 3);
                                        if (result == 1) {
                                            src2 = *(__int64 *)(ptr2 - 1);
                                            ptr3 = ptr2->field_7;
                                            result = ptr3->field_0;
                                            if (result != 0) {
                                                ((__int64 (*)())result)(src2);
                                            }
                                            --ptr2;
                                            if (ptr3->field_8 != 0) {
                                                v3 = ptr3->field_10;
                                                sub_14000ECF0(src2, v3);
                                            }
                                            off_140108030();
                                            off_140108038(result, 0, ptr2);
                                        }
                                    }
                                } else {
                                    src2 = (__int64 *)v_98;
                                    if (ptr2 == 1) {
                                        ptr2 = *(src - 1);
                                        ptr = *(src + 7);
                                        result = ptr->field_0;
                                        if (result != 0) {
                                            ((__int64 (*)())result)(ptr2);
                                        }
                                        --src;
                                        if (ptr->field_8 != 0) {
                                            v3 = ptr->field_10;
                                            sub_14000ECF0(ptr2, v3);
                                        }
                                        off_140108030();
                                        off_140108038(result, 0, src);
                                    }
                                    off_14012D180 = src2;
                                    ptr = 3;
                                    src = &off_14012D180;
                                }
                            }
                        } else {
                        }
                        if (*dst == 2) {
                            ptr2 = (struct Struct_3_t *)arg_8;
                            result = (struct Struct_1_t *)ptr2;
                            result = (struct Struct_1_t *)((__int64)(__int64)result & 3);
                            if (result == 1) {
                                src2 = *(__int64 *)(ptr2 - 1);
                                ptr4 = ptr2->field_7;
                                result = ptr4->field_0;
                                if (result != 0) {
                                    ((__int64 (*)())result)(src2);
                                }
                                --ptr2;
                                if (ptr4->field_8 != 0) {
                                    if (ptr4->field_10 >= 17) {
                                        src2 = *(src2 - 8);
                                    }
                                    off_140108030();
                                    off_140108038(result, 0, src2);
                                }
                                off_140108030();
                                off_140108038(result, 0, ptr2);
                            }
                        }
                        *dst = ptr;
                        arg_8 = (__int64)src;
                        return arg_8;
                }
                return arg_8;
            }
            return arg_8;
        }
        return (__int64)result;
    }
}