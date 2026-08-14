// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[16];
    __int64 field_30; // offset 48
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

__int64 sub_140063020();
__int64 sub_14005A9A0();
__int64 sub_1400617D0();

__int64 __fastcall sub_140062B40(__int64 *a1, __int64 *str) {
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
    int v_1b0;
    int v_1c0;
    int v_1d0;
    int v_20;
    int v_28;
    int v_2a0;
    int v_2b0;
    int v_2c0;
    int v_2d0;
    int v_2e0;
    int v_2f0;
    int v_30;
    int v_300;
    int v_310;
    int v_320;
    int v_330;
    int v_340;
    int v_38;
    int v_48;
    int v_58;
    int v_68;
    int v_78;
    int v_88;
    int v_98;
    int v_a8;
    int v_b8;
    int v_c8;
    int v_d0;
    int v_e0;
    int v_f0;
    struct Struct_2_t *ptr2;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 v8;
    __int64 v9;
    __m128i xmm0;
    __int64 v7;
    __int64 v2;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v6;
    __int64 v5;

    ptr2 = (struct Struct_2_t *)str;
    ptr = (struct Struct_1_t *)a1;
    a1 = rsp + 32;
    sub_140063020(a1);
    result = v_20;
    v8 = v_28;
    v9 = v_30;
    if (result != 3) {
        a1 = (__int64 *)v_48;
        ptr->field_30 = a1;
        xmm0 = _mm_loadu_si128((__m128i *)&v_38);
        _mm_storeu_si128((__m128i *)(ptr + 32), xmm0);
        ptr->field_8 = result;
        ptr->field_10 = v8;
        ptr->field_18 = v9;
    } else {
        v7 = ptr2->field_0;
        v2 = ptr2->field_10;
        a1 = rsp + 32;
        sub_14005A9A0(a1, ptr2);
        result = v_20;
        if (result != 8) {
            v2 -= v7;
            xmm0 = _mm_loadu_si128((__m128i *)&v_28);
            xmm1 = _mm_loadu_si128((__m128i *)&v_38);
            xmm2 = _mm_loadu_si128((__m128i *)&v_48);
            xmm3 = _mm_loadu_si128((__m128i *)&v_58);
            _mm_store_si128((__m128i *)&v_1d0, xmm2);
            _mm_store_si128((__m128i *)&v_1c0, xmm1);
            _mm_store_si128((__m128i *)&v_1b0, xmm0);
            _mm_storeu_si128((__m128i *)&v_2d0, xmm3);
            xmm0 = _mm_loadu_si128((__m128i *)&v_68);
            _mm_storeu_si128((__m128i *)&v_2e0, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_78);
            _mm_storeu_si128((__m128i *)&v_2f0, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_88);
            _mm_storeu_si128((__m128i *)&v_300, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_98);
            _mm_storeu_si128((__m128i *)&v_310, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_a8);
            _mm_storeu_si128((__m128i *)&v_320, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_b8);
            a1 = (__int64 *)v_c8;
            v_340 = (int)a1;
            v6 = ptr2->field_10;
            v6 -= ptr2->field_0;
            _mm_storeu_si128((__m128i *)&v_330, xmm0);
            str = (__int64 *)result;
            xmm0 = _mm_load_si128((__m128i *)&v_1b0);
            xmm1 = _mm_load_si128((__m128i *)&v_1c0);
            xmm2 = _mm_load_si128((__m128i *)&v_1d0);
            _mm_storeu_si128((__m128i *)&v_2a0, xmm0);
            _mm_storeu_si128((__m128i *)&v_2b0, xmm1);
            _mm_storeu_si128((__m128i *)&v_2c0, xmm2);
            a1 = rsp + 32;
            sub_1400617D0(a1, str, v5, v6);
            result = v_20;
            xmm0 = _mm_loadu_si128((__m128i *)&v_28);
            _mm_store_si128((__m128i *)&v_d0, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_38);
            _mm_store_si128((__m128i *)&v_e0, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_48);
            _mm_store_si128((__m128i *)&v_f0, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_58);
            _mm_store_si128((__m128i *)&v_130, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_68);
            _mm_store_si128((__m128i *)&v_140, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_78);
            _mm_store_si128((__m128i *)&v_150, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_88);
            _mm_store_si128((__m128i *)&v_160, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_98);
            _mm_store_si128((__m128i *)&v_170, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_a8);
            _mm_store_si128((__m128i *)&v_180, xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)&v_b8);
            _mm_store_si128((__m128i *)&v_190, xmm0);
            a1 = (__int64 *)v_c8;
            v_1a0 = (int)a1;
            if (result != 8) JUMPOUT(0x140062ddb);
        } else {
            xmm0 = _mm_loadu_si128((__m128i *)&v_28);
            xmm1 = _mm_loadu_si128((__m128i *)&v_38);
            xmm2 = _mm_loadu_si128((__m128i *)&v_48);
            _mm_store_si128((__m128i *)&v_d0, xmm0);
            _mm_store_si128((__m128i *)&v_e0, xmm1);
            _mm_store_si128((__m128i *)&v_f0, xmm2);
        }
        xmm0 = _mm_load_si128((__m128i *)&v_d0);
        xmm1 = _mm_load_si128((__m128i *)&v_e0);
        xmm2 = _mm_load_si128((__m128i *)&v_f0);
        _mm_store_si128((__m128i *)&v_120, xmm2);
        _mm_store_si128((__m128i *)&v_110, xmm1);
        _mm_store_si128((__m128i *)&v_100, xmm0);
        _mm_storeu_si128((__m128i *)(ptr + 40), xmm2);
        _mm_storeu_si128((__m128i *)(ptr + 24), xmm1);
        _mm_storeu_si128((__m128i *)(ptr + 8), xmm0);
    }
    *(__int64 *)ptr = (__int64)(12);
    return result;
}