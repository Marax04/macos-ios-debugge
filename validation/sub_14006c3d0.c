// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[96];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
};

__int64 sub_1400F27F0();
__int64 sub_14006C680();
__int64 sub_1400F3600();
__int64 sub_1400F2808();
__int64 sub_14006C597();
extern __int64 off_140117110;

__int64 __fastcall sub_14006C3D0(struct Struct_1_t *a1, size_t *a2, int a3) {
    __int64 rsp;
    int v_20;
    int v_30;
    int v_40;
    int v_50;
    __int64 *dst;
    __int64 *dst2;
    __int64 v2;
    __int64 v10;
    __int64 result;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 v11;
    __int64 v8;
    __int64 v9;
    __int64 v5;
    __int64 v6;
    __int64 v7;

    dst = (__int64 *)a3;
    dst2 = (__int64 *)a1;
    a1->field_68 = a1->field_68 + a3;
    v2 = (__int64)a2;
    a1 = a1->field_60;
    if (a1 != 0) {
        v10 = 64;
        v10 -= (__int64)a1;
        if (dst < v10) v10 = dst;
        a2 = v10 + a1;
        if (a2 >= a1) {
            if (a2 < 65) {
                a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst2);
                sub_1400F27F0(a1, v2, v10);
                result = *(dst2 + 96);
                result += v10;
                *(dst2 + 96) = result;
                dst -= v10;
                v2 += v10;
                if (result == 64) {
                    xmm0 = _mm_loadu_si128((__m128i *)dst2);
                    xmm1 = _mm_loadu_si128((__m128i *)(dst2 + 16));
                    xmm2 = _mm_loadu_si128((__m128i *)(dst2 + 32));
                    xmm3 = _mm_loadu_si128((__m128i *)(dst2 + 48));
                    _mm_store_si128((__m128i *)&v_50, xmm3);
                    _mm_store_si128((__m128i *)&v_40, xmm2);
                    _mm_store_si128((__m128i *)&v_30, xmm1);
                    _mm_store_si128((__m128i *)&v_20, xmm0);
                    a1 = dst2 + 64;
                    a2 = rsp + 32;
                    sub_14006C680(a1, a2);
                    *(dst2 + 96) = 0;
                }
                v10 = (__int64)dst;
                v10 &= 63;
                dst = (__int64 *)((__int64)(__int64)dst & -64);
                if (!((dst == 0))) {
                    v11 = dst2 + 64;
                    v8 = (__int64)dst;
                    v8 = -v8;
                    do {
                        v9 = a2 + 64;
                        sub_14006C680(v11, v2);
                        a2 = (size_t *)v9;
                        v8 += 64;
                    } while ((v8 != 0));
                }
                if (v10 != 0) {
                    v2 += (__int64)dst;
                    sub_1400F27F0(dst2, v2, v10);
                    *(dst2 + 96) = v10;
                }
                return v2;
            }
        }
        v5 = &off_140117110;
        sub_1400F3600(a1, a2, 64, v5);
        v6 = a2[12];
        if (v6 > 63) JUMPOUT(0x14006c65c);
        dst = (__int64 *)a2;
        dst2 = (__int64 *)a1;
        v7 = a2[13];
        *(a2 + v6) = 128;
        a1 = v6 + 1;
        if (v6 < 56) JUMPOUT(0x14006c591);
        if (a1 != 64) {
            a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)dst);
            a3 = 63;
            a3 -= v6;
            sub_1400F2808(a1, 0, a3);
        }
        xmm0 = _mm_loadu_si128((__m128i *)dst);
        xmm1 = _mm_loadu_si128((__m128i *)(dst + 16));
        xmm2 = _mm_loadu_si128((__m128i *)(dst + 32));
        xmm3 = _mm_loadu_si128((__m128i *)(dst + 48));
        _mm_store_si128((__m128i *)&v_50, xmm3);
        _mm_store_si128((__m128i *)&v_40, xmm2);
        _mm_store_si128((__m128i *)&v_30, xmm1);
        _mm_store_si128((__m128i *)&v_20, xmm0);
        a1 = dst + 64;
        a2 = rsp + 32;
        sub_14006C680(a1, a2);
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)(dst + 32), xmm0);
        _mm_storeu_si128((__m128i *)(dst + 16), xmm0);
        _mm_storeu_si128((__m128i *)dst, xmm0);
        *(dst + 48) = 0;
        a1 = 0;
        return sub_14006C597();
    }
    return result;
}