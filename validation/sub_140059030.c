// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

extern __int64 off_140116C0C;

__int64 __fastcall sub_140059030(__int64 *a1,struct Struct_1_t *a2, __int64 a3) {
    __int64 rsp;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    __int64 v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_70;
    int v_80;
    __int64 i;
    __int64 *src;
    __m128i xmm0;
    __int64 *dst;
    __int64 result;
    int v6;
    __int64 v7;
    int v2;
    __int64 v9;
    __m128i xmm1;
    __int64 v8;

    i = a2->field_18;
    if (i != 0) {
        src = a2->field_10;
        if (*src != 39) {
            *a1 = 1;
            *(a1 + 8) = 0;
            a1[2] = 8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
        } else {
            dst = (__int64 *)i;
            --dst;
            if (!((dst == 0))) {
                result = src + 1;
                a3 = 0;
                do {
                    v6 = *(src + a3 + 1);
                    v7 = v6;
                    v2 = v7 - 32;
                    ++a3;
                } while (dst != a3);
            }
            src += i;
            a2->field_10 = src;
            a2->field_18 = 0;
            *a1 = 2;
            *(a1 + 8) = 0;
            a1[2] = 8;
            xmm0 = _mm_setzero_si128();
            _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
            v_48 = 0;
            result = a1[2];
            a2 = a1[3];
            xmm0 = _mm_loadu_si128((__m128i *)(a1 + 32));
            v_50 = result;
            v_58 = (int)a2;
            _mm_storeu_si128((__m128i *)&v_60, xmm0);
            i = v_58;
            if (i == 0) JUMPOUT(0x1400592dc);
            result = 0;
            a2 = a1 + 8;
            a1 += 16;
            a3 = rsp + 80;
            dst = (__int64 *)v_50;
            v9 = i + i*2;
            dst[v9] = 3;
            v7 = &off_140116C0C;
            *(dst + v9*8 + 8) = v7;
            *(dst + v9*8 + 16) = 14;
            ++i;
            v_58 = i;
            xmm0 = _mm_loadu_si128((__m128i *)a3);
            xmm1 = _mm_loadu_si128((__m128i *)(a3 + 16));
            _mm_store_si128((__m128i *)&v_80, xmm1);
            _mm_store_si128((__m128i *)&v_70, xmm0);
            *(__int64 *)a2 = (__int64)(result);
            xmm0 = _mm_load_si128((__m128i *)&v_70);
            xmm1 = _mm_load_si128((__m128i *)&v_80);
            _mm_storeu_si128((__m128i *)(a1 + 16), xmm1);
            _mm_storeu_si128((__m128i *)a1, xmm0);
            return 0;
        }
        v_20 = 0;
        result = a1[2];
        a2 = a1[3];
        a3 = a1[4];
        dst = a1[5];
        v_28 = result;
        v_30 = (int)a2;
        v_38 = a3;
        v_40 = (__int64)dst;
        i = v_30;
        if (i == 0) JUMPOUT(0x1400592bf);
        result = 0;
        a2 = a1 + 8;
        a1 += 16;
        a3 = rsp + 40;
        dst = (__int64 *)v_28;
        v8 = i + i*2;
        dst[v8] = 3;
        v7 = &off_140116C0C;
        *(dst + v8*8 + 8) = v7;
        *(dst + v8*8 + 16) = 14;
        ++i;
        v_30 = i;
        return v_30;
    }
    return result;
}