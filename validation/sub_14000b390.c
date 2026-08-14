// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[618];
    __int64 field_272; // offset 626
};

__int64 sub_1400F27FC();
__int64 sub_14000B578();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14000B390(__int64 *a1,struct Struct_1_t *a2,struct Struct_2_t *a3, __int64 a4) {
    __int64 v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_90;
    int v_a0;
    struct Struct_3_t *result;
    __int64 v3;
    __int64 i;
    __int64 v2;
    __int64 v8;
    __int64 v7;
    __int64 v9;
    __int64 v10;
    __int64 v5;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;

    result = a2->field_0;
    if (result == 0) {
        v3 = a3->field_0;
        result = a3->field_8;
        v_20 = (__int64)result;
        result = (struct Struct_3_t *)v3;
        result = (struct Struct_3_t *)(-(__int64)result);
        if ((0 /* overflow check on (-result) */)) JUMPOUT(0x14000b4fe);
        i = (__int64)a2;
    } else {
        v_30 = a4;
        v_38 = (int)a1;
        v_40 = (int)a2;
        v2 = a2->field_8;
        v8 = a3->field_8;
        v_48 = (int)a3;
        v7 = ((__int64 *)a3)[2];
        do {
            a1 = result + 360;
            v_20 = (__int64)result;
            result = result->field_272;
            v9 = (__int64)result;
            result =  + (__int64)(__int64)result*8;
            v3 = result + (__int64)(__int64)result*2;
            i = -1;
            v_28 = (int)a1;
            while (v3 != 0) {
                v10 = a1 + 24;
                a2 = *(a1 + 8);
                v5 = a1[2];
                v6 = v7;
                v6 -= v5;
                if (v6 < 0) v5 = v7;
                sub_1400F27FC(v8, a2, v5);
                if (result != 0) v6 = result;
                a1 = (v6 < 0) ? 1 : 0;
                result = (v6 > 0) ? 1 : 0;
                result = (struct Struct_3_t *)((__int64)result - (__int64)a1);
                v3 -= 24;
                ++i;
                if (result != 0) {
                    --v2;
                    if ((v2 < 0)) JUMPOUT(0x14000b58c);
                    result = (struct Struct_3_t *)v_20;
                    result = *(__int64 *)(result + i*8 + 632);
                }
                result = (struct Struct_3_t *)v_48;
                if (result->field_0 != 0) {
                    off_140108030(v10);
                    off_140108038(result, 0, v8);
                }
                a1 = (__int64 *)v_38;
                a4 = v_30;
                i <<= 5;
                result = (struct Struct_3_t *)v_20;
                xmm0 = _mm_loadu_si128((__m128i *)(result + i));
                xmm1 = _mm_loadu_si128((__m128i *)(result + i + 16));
                _mm_store_si128((__m128i *)&v_a0, xmm1);
                _mm_store_si128((__m128i *)&v_90, xmm0);
                xmm0 = _mm_loadu_si128((__m128i *)a4);
                xmm1 = _mm_loadu_si128((__m128i *)(a4 + 16));
                _mm_storeu_si128((__m128i *)(result + i + 16), xmm1);
                _mm_storeu_si128((__m128i *)(result + i), xmm0);
                xmm0 = _mm_load_si128((__m128i *)&v_90);
                xmm1 = _mm_load_si128((__m128i *)&v_a0);
                _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
                _mm_storeu_si128((__m128i *)a1, xmm0);
                return sub_14000B578();
            }
            i = v9;
            return i;
        } while (true);
    }
    return (__int64)result;
}