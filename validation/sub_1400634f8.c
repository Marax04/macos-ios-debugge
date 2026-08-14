// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[136];
    __int64 field_A8; // offset 168
};

__int64 sub_1400617D0();
__int64 sub_140046190();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400634F8(__int64 *a1) {
    __int64 rsp;
    int v_100;
    int v_110;
    int v_120;
    int v_130;
    int v_140;
    int v_150;
    int v_160;
    int v_170;
    int v_180;
    int v_190;
    int v_1a0;
    int v_1e0;
    int v_1e8;
    int v_1f0;
    int v_1f8;
    int v_200;
    int v_208;
    int v_218;
    int v_228;
    int v_238;
    int v_248;
    int v_258;
    int v_268;
    int v_278;
    int v_288;
    int v_290;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_68;
    int v_78;
    int v_88;
    int v_98;
    int v_a8;
    int v_b8;
    int v_c8;
    int v_d8;
    int v_e0;
    int v_f8;
    __int64 result;
    __int64 v6;
    __int64 v10;
    __int64 v3;
    __int64 v12;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v7;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v9;
    __int64 v5;
    __int64 v8;
    __int64 v13;
    struct Struct_2_t *ptr2;

    result = v_30;
    v6 = v_38;
    v10 = v_40;
    v3 = v_48;
    v12 = v_50;
    xmm0 = _mm_loadu_si128((__m128i *)&v_58);
    _mm_store_si128((__m128i *)&v_290, xmm0);
    if (result != 8) {
        a1 = (__int64 *)v_d8;
        v_288 = (int)a1;
        xmm0 = _mm_loadu_si128((__m128i *)&v_c8);
        _mm_storeu_si128((__m128i *)&v_278, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_b8);
        _mm_storeu_si128((__m128i *)&v_268, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_a8);
        _mm_storeu_si128((__m128i *)&v_258, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_68);
        xmm1 = _mm_loadu_si128((__m128i *)&v_78);
        xmm2 = _mm_loadu_si128((__m128i *)&v_88);
        xmm3 = _mm_loadu_si128((__m128i *)&v_98);
        _mm_storeu_si128((__m128i *)&v_248, xmm3);
        _mm_storeu_si128((__m128i *)&v_238, xmm2);
        _mm_storeu_si128((__m128i *)&v_228, xmm1);
        v7 = ptr->field_10;
        v7 -= ptr->field_0;
        _mm_storeu_si128((__m128i *)&v_218, xmm0);
        v_1e0 = result;
        v_1e8 = v6;
        v_1f0 = v10;
        v_1f8 = v3;
        v_200 = v12;
        xmm0 = _mm_load_si128((__m128i *)&v_290);
        _mm_storeu_si128((__m128i *)&v_208, xmm0);
        a1 = rsp + 48;
        v3 = rsp + 480;
        sub_1400617D0(a1, v3, v2, v7);
        v7 = v_30;
        v6 = v_38;
        v10 = v_40;
        a1 = (__int64 *)v_48;
        v3 = v_50;
        xmm0 = _mm_loadu_si128((__m128i *)&v_58);
        _mm_store_si128((__m128i *)&v_1a0, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_68);
        _mm_store_si128((__m128i *)&v_110, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_78);
        _mm_store_si128((__m128i *)&v_120, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_88);
        _mm_store_si128((__m128i *)&v_130, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_98);
        _mm_store_si128((__m128i *)&v_140, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_a8);
        _mm_store_si128((__m128i *)&v_150, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_b8);
        _mm_store_si128((__m128i *)&v_160, xmm0);
        xmm0 = _mm_loadu_si128((__m128i *)&v_c8);
        _mm_store_si128((__m128i *)&v_170, xmm0);
        result = v_d8;
        v_180 = result;
        if (v7 != 8) JUMPOUT(0x140063977);
        v12 = v3;
        ptr = (struct Struct_1_t *)a1;
    } else {
        ptr = (struct Struct_1_t *)v3;
        xmm0 = _mm_load_si128((__m128i *)&v_290);
        _mm_store_si128((__m128i *)&v_1a0, xmm0);
    }
    xmm0 = _mm_load_si128((__m128i *)&v_1a0);
    _mm_store_si128((__m128i *)&v_e0, xmm0);
    v2 = v6;
    xmm0 = _mm_load_si128((__m128i *)&v_e0);
    _mm_store_si128((__m128i *)&v_190, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm0);
    if (v2 != 2) v13 = v2;
    xmm0 = _mm_load_si128((__m128i *)&v_30);
    _mm_store_si128((__m128i *)&v_100, xmm0);
    if (v9 != 0) {
        v2 = v5;
        do {
            sub_140046190(v2, v3, v6, v7);
            v2 += 144;
            --v9;
        } while ((v9 != 0));
    }
    if (v_f8 != 0) {
        off_140108030();
        off_140108038(result, 0, v5);
    }
    v5 = (__int64)ptr;
    v8 = v12;
    xmm0 = _mm_load_si128((__m128i *)&v_100);
    _mm_storeu_si128((__m128i *)(ptr2 + 32), xmm0);
    *(__int64 *)ptr2 = (__int64)(v13);
    ptr2->field_8 = v10;
    ptr2->field_10 = v5;
    ptr2->field_18 = v8;
    ptr2->field_A8 = 12;
    return result;
}