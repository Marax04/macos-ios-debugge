// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    char _pad_18[8];
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140054AA0();
__int64 sub_1400586CA();
__int64 sub_140058677();
__int64 sub_14004F470();
__int64 sub_140058685();

__int64 __fastcall sub_140058580(__int64 *a1, int *a2) {
    __int64 rsp;
    int v_28;
    int v_30;
    int v_38;
    int v_39;
    int v_48;
    int v_50;
    int v_60;
    int v_68;
    char *str;
    struct Struct_2_t *ptr2;
    __int64 v1;
    struct Struct_1_t *ptr;
    __int64 i;
    __int64 v5;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *i2;
    __int64 v6;
    __int64 v4;

    ptr2 = (struct Struct_2_t *)a2;
    v1 = a2[2];
    v1 -= *a2;
    ptr = (struct Struct_1_t *)a1;
    v_50 = 0;
    v_60 = 0;
    v_68 = 0x920;
    i = rsp + 32;
    a2 = rsp + 80;
    sub_140054AA0(i, a2);
    v5 = (__int64)str;
    if (v5 != 3) {
        xmm0 = _mm_loadu_si128((__m128i *)&v_28);
        a1 = (__int64 *)v_38;
        xmm1 = _mm_loadu_si128((__m128i *)&v_39);
        _mm_storeu_si128((__m128i *)(ptr + 25), xmm1);
        a2 = (int *)v_48;
        ptr->field_28 = a2;
        *(__int64 *)ptr = (__int64)(v5);
        _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
        ptr->field_18 = a1;
        return sub_1400586CA();
    } else {
        i2 = ptr2->field_10;
        v6 = ptr2->field_18;
        if (v6 != 0) {
            if (*i2 == 35) {
                ++i2;
                a1 = 0;
                --v6;
                if ((v6 != 0)) {
                    do {
                        a2 = *(i2 + i);
                        ++i;
                        if (v6 == i) JUMPOUT(0x140058674);
                    } while (true);
                } else {
                    return sub_140058677();
                }
            }
        }
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_38, xmm0);
        str = 1;
        v_28 = 0;
        v_30 = 8;
        sub_14004F470(str, a2, v4);
        return sub_140058685();
    }
}