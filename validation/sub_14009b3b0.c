// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
};

__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_1400F3600();
__int64 sub_1400F3340();
__int64 sub_1400F37D0();
extern __int64 off_14011D8B0;
extern __int64 off_14011D898;
extern __int64 off_14011D858;
extern __int64 off_14011D880;

__int64 __fastcall sub_14009B3B0(size_t *a1, size_t *a2) {
    int v_2c;
    int v_30;
    int v_40;
    int v_4c;
    int v_50;
    int v_58;
    __int64 v_60;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 v9;
    __int64 *dst2;
    __int64 v10;
    __int64 *result;
    __int64 v11;
    __m128i xmm0;
    __int64 v13;
    __int64 *dst3;
    __int64 v6;
    __m128i xmm1;
    __int64 v7;
    __int64 v8;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    dst = *a2;
    v9 = *(dst + 318);
    sub_14002EDF0(0, 416);
    if (result != 0) {
        dst2 = result;
        *result = 0;
        v10 = ptr->field_10;
        result = *(dst + 318);
        v11 = v10;
        v11 = ~v11;
        v11 += (__int64)result;
        *(dst2 + 318) = v11;
        a2 = *(dst + v10*4 + 272);
        result =  + v10*2;
        result += v10;
        a1 = *(dst + (__int64)(__int64)result*8 + 24);
        v_40 = (int)a1;
        xmm0 = _mm_loadu_si128((__m128i *)(dst + (__int64)(__int64)result*8 + 8));
        _mm_store_si128((__m128i *)&v_30, xmm0);
        if (v11 < 12) {
            v_2c = (int)a2;
            result = dst + 272;
            v13 = dst + 8;
            a1 = dst2 + 272;
            a2 = result + v10*4;
            a2 += 4;
            dst3 =  + v11*4;
            sub_1400F27F0(a1, a2, dst3);
            a1 = dst2 + 8;
            result =  + v10*2 + 3;
            result += v10;
            a2 =  + (__int64)(__int64)result*8;
            a2 += v13;
            v11 <<= 3;
            dst3 = v11 + v11*2;
            sub_1400F27F0(a1, a2, dst3);
            *(dst + 318) = v10;
            xmm0 = _mm_load_si128((__m128i *)&v_30);
            _mm_storeu_si128((__m128i *)&v_50, xmm0);
            result = (__int64 *)v_40;
            v_60 = (__int64)result;
            v11 = *(dst2 + 318);
            dst3 = v11 + 1;
            if (v11 >= 12) {
                v6 = &off_14011D8B0;
                sub_1400F3600(0, dst3, 12, v6);
                sub_1400F3340(8, 416);
                v6 = &off_14011D898;
                sub_1400F3600(0, v11, 11, v6);
            } else {
                v9 -= v10;
                if (v9 == dst3) {
                    a1 = (size_t *)dst2;
                    a1 += 320;
                    a2 = dst + v10*8;
                    a2 += 328;
                    dst3 = (__int64 *)((__int64)(__int64)dst3 << 3);
                    sub_1400F27F0(a1, a2, dst3);
                    result = ptr->field_8;
                    a1 = 0;
                    a2 = a1;
                    a1 += 0;
                    dst3 = *(dst2 + (__int64)(__int64)a2*8 + 320);
                    *dst3 = dst2;
                    *(dst3 + 316) = a2;
                    while (a2 < v11) {
                    }
                    xmm0 = _mm_loadu_si128((__m128i *)&v_4c);
                    xmm1 = _mm_loadu_si128((__m128i *)&v_58);
                    _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
                    _mm_storeu_si128((__m128i *)(ptr2 + 4), xmm0);
                    ptr2->field_20 = dst;
                    ptr2->field_28 = result;
                    a1 = (size_t *)v_2c;
                    *(__int64 *)ptr2 = (__int64)(a1);
                    ptr2->field_30 = dst2;
                    ptr2->field_38 = result;
                    return (__int64)a1;
                }
            }
            a1 = &off_14011D858;
            dst3 = &off_14011D880;
            sub_1400F37D0(a1, 40, dst3);
            if (a2 < a1[5]) {
                result = a1[2];
                v6 = a1[8];
                v7 = a2 + (__int64)(__int64)a2*4;
                v8 = v6 + v7*8;
                v8 += 36;
                v7 = v6 + v7*8;
                v7 += 40;
                if (v7 < v8) JUMPOUT(0x14009b611);
                if (v7 > result) JUMPOUT(0x14009b611);
                result = *(a1 + 8);
                *(result + v8) = dst3;
                result = a1[4];
                a1 = a2 + (__int64)(__int64)a2*8;
                a1 += (__int64)(__int64)a1*2;
                a1 = (size_t *)((__int64)a1 + (__int64)a2);
                *(__int64 *)((__int64)result + (__int64)a1 + 24) = dst3;
            }
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return (__int64)result;
}