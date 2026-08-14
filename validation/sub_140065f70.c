// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140067107();
__int64 sub_14004F470();
__int64 sub_1400660D0();

__int64 __fastcall sub_140065F70(int a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int arg_1;
    int v_158;
    int v_159;
    int v_15d;
    int v_15f;
    int v_160;
    int v_168;
    int v_178;
    int v_1f0;
    int v_a0;
    int v_a1;
    int v_a5;
    int v_a7;
    int v_a8;
    int v_b0;
    int v_b8;
    int v_c0;
    char *str;
    struct Struct_2_t *ptr;
    __int64 *v7;
    __int64 v2;
    __int64 v5;
    int v1;
    __m128i xmm0;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_1f0, xmm6);
    ptr = (struct Struct_2_t *)a2;
    v7 = a2->field_10;
    v2 = a2->field_18;
    if (v2 > 1) {
        if (*v7 != 48) JUMPOUT(0x1400660d0);
        v5 = v2 - 2;
        v1 = arg_1;
        if (v1 == 98) JUMPOUT(0x1400665eb);
        if (v1 == 111) JUMPOUT(0x14006635d);
        if (v1 != 120) JUMPOUT(0x1400660d0);
        ptr->field_10 = str;
        ptr->field_18 = v5;
        if (v2 != 2) JUMPOUT(0x140066a0c);
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_168, xmm0);
        v_158 = 0;
        v_15f = 0;
        v_15d = 0;
        v_159 = 0;
        v_160 = 8;
        v_c0 = v_178;
        _mm_store_si128((__m128i *)&v_b0, xmm0);
        a1 = v_158;
        v_a0 = a1;
        a1 = v_159;
        v_a1 = a1;
        a1 = v_15d;
        v_a5 = a1;
        a1 = v_15f;
        v_a7 = a1;
        v_a8 = v_160;
        return sub_140067107();
    } else {
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_b8, xmm0);
        v_a0 = 1;
        v_a8 = 0;
        v_b0 = 8;
        a1 = rsp + 160;
        sub_14004F470(a1);
        return sub_1400660D0();
    }
}