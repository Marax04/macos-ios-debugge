// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140028050();
__int64 sub_14002DC40();
__int64 sub_1400371B0();
__int64 sub_140037460();
__int64 sub_140037EA0();
__int64 sub_140041110();
__int64 sub_14002E220();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140113DF0;
extern __int64 off_140124F80;
extern __int64 off_14012D220;
extern __int64 off_140113D10;
extern __int64 off_140108418;

__int64 __fastcall sub_1400412CF(int *a1, int *a2, __int64 a3, __int64 a4) {
    int arg_d;
    int arg_e;
    int arg_f;
    __int64 v_10;
    int v_14;
    __int64 v_20;
    int v_28;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_8;
    __int64 src;
    __m128i xmm0;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v6;
    __int64 *src2;
    struct Struct_3_t *ptr3;
    __int64 *src3;
    __int64 *dst2;
    __int64 *dst;
    struct Struct_2_t *ptr2;

    v_14 = 0;
    src = &off_140113DF0;
    v_60 = src;
    v_58 = 1;
    v_50 = 8;
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_48, xmm0);
    a1 = dst - 24;
    a2 = dst - 96;
    sub_140028050(a1, a2);
    v_28 = src;
    if (src != 0) {
        a1 = dst - 40;
        sub_14002DC40(a1);
    }
    a1 = 7;
    /* int $41 */;
    a2 += 96;
    *a2 = src;
    a1 = a4 + 104;
    a2 = ptr2 + 16;
    a3 = off_140124F80;
    *a1 = a2;
    a1 = ptr2->field_18;
    if (a1 == 0) {
        a1 = off_14012D220;
        if (a1 == src) {
            a1 = &off_140113D10;
            arg_f = 1;
            arg_e = 1;
            sub_1400371B0(a1, 5, off_140108418);
        }
    } else {
        a2 = ptr2->field_20;
        return (__int64)a2;
    }
    ptr = (struct Struct_1_t *)v_8;
    v5 = ptr->field_30;
    a1 = ptr->field_38;
    xmm0 = _mm_loadu_si128((__m128i *)(ptr + 16));
    _mm_store_si128((__m128i *)&v_50, xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)ptr);
    _mm_store_si128((__m128i *)&v_60, xmm0);
    *dst = v5;
    v_40 = v5;
    v_10 = (__int64)a1;
    v_38 = (int)a1;
    arg_d = 1;
    a1 = dst - 96;
    sub_140037460(a1);
    arg_d = 0;
    a1 = *dst;
    a2 = (int *)v_10;
    sub_140037EA0(a1, a2);
    ptr = ptr->field_28;
    if (ptr->field_18 != 0) {
        v6 = ptr->field_20;
        if (v6 != 0) {
            *dst = v6;
            v_20 = (__int64)ptr;
            src2 = ptr->field_28;
            v_10 = (__int64)src2;
            src2 = *src2;
            if (src2 != 0) {
                a1 = *dst;
                ((__int64 (*)())src2)(a1);
            }
            ptr3 = (struct Struct_3_t *)v_10;
            ptr = (struct Struct_1_t *)v_20;
            src3 = *dst;
            if (ptr3->field_8 != 0) {
                if (ptr3->field_10 >= 17) {
                    src3 = *(src3 - 8);
                }
                off_140108030();
                off_140108038(ptr3, 0, src3);
            }
        }
    }
    ptr->field_18 = 1;
    ptr->field_20 = 0;
    *(__int64 *)ptr = (__int64)(ptr->field_0 - 1);
    if (!((ptr->field_0 != 0))) {
        arg_f = 0;
        arg_e = 0;
        sub_140041110(ptr);
    }
    a1 = (int *)v_8;
    dst2 = a1[4];
    *dst2 = *dst2 - 1;
    if ((*dst2 != 0)) JUMPOUT(0x14004146f);
    a1 = a1[4];
    return sub_14002E220();
}