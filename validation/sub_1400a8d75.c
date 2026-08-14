// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    int field_8; // offset 8
    int field_C; // offset 12
    __int64 field_10; // offset 16
    char _pad_10[28];
    __int64 field_34; // offset 52
};

__int64 sub_1400B1470();
__int64 sub_1400A91F2();
__int64 sub_1400A7B50();
__int64 off_140108038();
__int64 off_140108030();

__int64 __fastcall sub_1400A8D75(int *a1, int a2) {
    __int64 rsp;
    int v_190;
    int v_1a0;
    __int64 v_1b0;
    int v_358;
    int v_368;
    int v_370;
    int v_430;
    int v_440;
    int v_450;
    int v_454;
    int v_464;
    int v_70;
    int v_910;
    int v_918;
    int v_91c;
    int v_920;
    int v_924;
    int v_934;
    __int64 v_944;
    int v_f30;
    int v_f40;
    int v_f50;
    int v_f60;
    __int64 v12;
    __int64 v5;
    __int64 *result;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __int64 v6;
    __int64 v7;
    __int64 v8;
    int v10;
    __int64 v2;
    __int64 v3;
    __int64 v4;
    int v11;
    struct Struct_1_t *ptr;

    *(result - 119) = *(result - 119) + a1;
    *a1 = *a1 << 210;
    off_140108038(a1, a2, v3);
    if (v4 == 0) {
        a1 = rsp + 0x910;
        sub_1400B1470(a1, a2, v5, v6);
    } else {
        v12 = 0x8000000000000001;
        off_140108030();
        v5 = v_70;
        off_140108038(result, 0, v5);
        a1 = rsp + 0x910;
        sub_1400B1470(a1);
        result = 0x8000000000000001;
        if (v12 != result) {
            result = (__int64 *)v_450;
            v_1b0 = (__int64)result;
            xmm0 = _mm_load_si128((__m128i *)&v_430);
            xmm1 = _mm_load_si128((__m128i *)&v_440);
            _mm_store_si128((__m128i *)&v_1a0, xmm1);
            _mm_store_si128((__m128i *)&v_190, xmm0);
            xmm2 = _mm_loadu_si128((__m128i *)&v_454);
            _mm_store_si128((__m128i *)&v_f50, xmm2);
            xmm2 = _mm_loadu_si128((__m128i *)&v_464);
            _mm_store_si128((__m128i *)&v_f60, xmm2);
            v_944 = (__int64)result;
            _mm_storeu_si128((__m128i *)&v_934, xmm1);
            _mm_storeu_si128((__m128i *)&v_924, xmm0);
            v_910 = v12;
            v_918 = v10;
            v_91c = v11;
            v_920 = v8;
            result = (__int64 *)v_368;
            v6 = v_370;
            a1 = v6 + v6*8;
            a1 += (__int64)(__int64)a1*2;
            a1 += v6;
            v7 = 0x747865742E;
            if (v6 != 0) {
                v5 = 0;
                a2 = 0;
                while (*(result + v5) != v7) {
                    ++a2;
                    v5 += 28;
                    xmm0 = _mm_setzero_si128();
                    _mm_store_si128((__m128i *)&v_f40, xmm0);
                    _mm_store_si128((__m128i *)&v_f30, xmm0);
                    v8 = 1;
                    v10 = 0;
                    if (v6 == 0) JUMPOUT(0x1400a91f2);
                    v5 = 0;
                    a2 = 0;
                    for (; a1 != v5; v5 += 28) {
                        if (*(result + v5) == v7) JUMPOUT(0x1400a9067);
                        ++a2;
                    }
                    return sub_1400A91F2();
                }
                v5 = a2 + a2*8;
                v2 = v5 + v5*2;
                v2 += a2;
                v5 = *(result + v2 + 16);
                a2 = *(result + v2 + 20);
                v8 = v5 + a2;
                if (v8 <= v_358) JUMPOUT(0x1400a90b6);
            }
            return (__int64)result;
        }
    }
    result = (__int64 *)v_450;
    v_1b0 = (__int64)result;
    xmm0 = _mm_load_si128((__m128i *)&v_430);
    xmm1 = _mm_load_si128((__m128i *)&v_440);
    _mm_store_si128((__m128i *)&v_1a0, xmm1);
    _mm_store_si128((__m128i *)&v_190, xmm0);
    ptr->field_34 = result;
    _mm_storeu_si128((__m128i *)(ptr + 36), xmm1);
    _mm_storeu_si128((__m128i *)(ptr + 20), xmm0);
    ptr->field_8 = v10;
    ptr->field_C = v11;
    ptr->field_10 = v8;
    return sub_1400A7B50();
}