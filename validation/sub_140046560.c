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

// inferred from 3 accesses on `result`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F27FC();
__int64 sub_14004672A();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_140046560(int a1,struct Struct_1_t *a2,struct Struct_2_t *a3, __int64 a4) {
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_60;
    __int64 v3;
    __int64 *src;
    __int64 v5;
    __int64 v4;
    struct Struct_3_t *result;
    __int64 i;
    __int64 v9;
    __int64 v2;
    __int64 v10;
    __int64 v6;
    __int64 v11;
    __m128i xmm0;
    __m128i xmm1;

    v_28 = a4;
    v3 = a1;
    src = a2->field_0;
    v_40 = (int)a2;
    if (src == 0) {
        v5 = a3->field_8;
        v4 = ((__int64 *)a3)[2];
        src = 0;
        result = a3->field_0;
        a1 = (int)result;
        a1 = -a1;
        if ((0 /* overflow check on (-a1) */)) JUMPOUT(0x1400466d8);
        src = (__int64 *)v5;
        i = v_40;
    } else {
        v_30 = v3;
        v3 = a2->field_8;
        v9 = a3->field_8;
        v_38 = (int)a3;
        v4 = ((__int64 *)a3)[2];
        do {
            result = src + 360;
            a1 = *(src + 626);
            v_48 = a1;
            a1 =  + a1*8;
            v2 = a1 + a1*2;
            i = -1;
            while (v2 != 0) {
                v10 = result + 24;
                a2 = result->field_8;
                v6 = result->field_10;
                v11 = v4;
                v11 -= v6;
                if (v11 < 0) v6 = v4;
                sub_1400F27FC(v9, a2, v6);
                if (result != 0) v11 = result;
                result = (v11 < 0) ? 1 : 0;
                a1 = (v11 > 0) ? 1 : 0;
                a1 -= (__int64)result;
                v2 -= 24;
                ++i;
                result = (struct Struct_3_t *)v10;
                result = (struct Struct_3_t *)a1;
                if (a1 != 0) {
                    --v3;
                    if ((v3 < 0)) JUMPOUT(0x1400466c3);
                    src = *(src + i*8 + 632);
                }
                result = (struct Struct_3_t *)v_38;
                if (result->field_0 != 0) {
                    off_140108030(a1);
                    off_140108038(result, 0, v9);
                }
                v3 = v_30;
                result = (struct Struct_3_t *)v_28;
                i <<= 5;
                xmm0 = _mm_loadu_si128((__m128i *)(src + i));
                xmm1 = _mm_loadu_si128((__m128i *)(src + i + 16));
                _mm_store_si128((__m128i *)&v_60, xmm1);
                _mm_store_si128((__m128i *)&v_50, xmm0);
                xmm0 = _mm_loadu_si128((__m128i *)result);
                xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
                _mm_storeu_si128((__m128i *)(src + i + 16), xmm1);
                _mm_storeu_si128((__m128i *)(src + i), xmm0);
                xmm0 = _mm_load_si128((__m128i *)&v_50);
                xmm1 = _mm_load_si128((__m128i *)&v_60);
                _mm_storeu_si128((__m128i *)(v3 + 16), xmm1);
                _mm_storeu_si128((__m128i *)v3, xmm0);
                return sub_14004672A();
            }
            i = v_48;
            return i;
        } while (true);
    }
    return (__int64)result;
}