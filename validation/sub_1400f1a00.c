// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 6 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
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
__int64 sub_140011970();
extern __int64 off_14011D8B0;
extern __int64 off_14011D898;
extern __int64 off_14011D858;
extern __int64 off_14011D880;
extern __int64 off_14010B327;

__int64 __fastcall sub_1400F1A00(int *a1, int *a2) {
    __int64 rsp;
    __int64 v_20;
    int v_28;
    __int64 v_30;
    int v_40;
    int v_50;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 v9;
    __int64 *dst2;
    __int64 v10;
    __int64 *result;
    __int64 v11;
    __m128i xmm0;
    int v13;
    __int64 *dst3;
    __int64 v6;
    __int64 v8;
    __int64 v7;

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
        result =  + v10*2;
        result += v10;
        a1 = *(dst + (__int64)(__int64)result*8 + 24);
        v_50 = (int)a1;
        xmm0 = _mm_loadu_si128((__m128i *)(dst + (__int64)(__int64)result*8 + 8));
        _mm_store_si128((__m128i *)&v_40, xmm0);
        if (v11 < 12) {
            result = dst + 8;
            v13 = *(dst + v10*4 + 272);
            a1 = dst2 + 8;
            a2 =  + v10*2 + 3;
            a2 += v10;
            a2 = result + (__int64)(__int64)a2*8;
            result =  + v11*8;
            dst3 = result + (__int64)(__int64)result*2;
            sub_1400F27F0(a1, a2, dst3);
            a1 = dst2 + 272;
            a2 = dst + v10*4;
            a2 += 276;
            v11 <<= 2;
            sub_1400F27F0(a1, a2, v11);
            *(dst + 318) = v10;
            xmm0 = _mm_load_si128((__m128i *)&v_40);
            _mm_store_si128((__m128i *)&v_20, xmm0);
            result = (__int64 *)v_50;
            v_30 = (__int64)result;
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
                    a1 = (int *)dst2;
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
                    a1 = (int *)v_30;
                    ptr2->field_10 = a1;
                    xmm0 = _mm_load_si128((__m128i *)&v_20);
                    _mm_storeu_si128((__m128i *)ptr2, xmm0);
                    ptr2->field_20 = dst;
                    ptr2->field_28 = result;
                    ptr2->field_18 = v13;
                    ptr2->field_30 = dst2;
                    ptr2->field_38 = result;
                    return _mm_cvtsi128_si64(xmm0);
                }
            }
            a1 = &off_14011D858;
            dst3 = &off_14011D880;
            sub_1400F37D0(a1, 40, dst3);
            result = *a1;
            dst3 = *result;
            result = 10;
            a1 = &off_14010B327;
            v6 = (__int64)dst3;
            if (dst3 >= 1000) {
                v8 = 10;
                v7 = 0xD1B71759;
                ptr2 = (struct Struct_2_t *)dst3;
                do {
                    result = v8 - 4;
                    v6 = (__int64)ptr2;
                    v6 *= v7;
                    v6 >>= 45;
                    dst2 = v6 * 0x2710;
                    ptr = (struct Struct_1_t *)ptr2;
                    ptr = (struct Struct_1_t *)((__int64)ptr - (__int64)dst2);
                    dst2 = (__int64)(__int64)ptr * 0x147B;
                    dst2 = (__int64 *)((__int64)(__int64)dst2 >> 19);
                    v13 = (__int64)(__int64)dst2 * 100;
                    ptr -= v13;
                    dst2 = *(a1 + (__int64)(__int64)dst2*2);
                    xmm0 = _mm_cvtsi32_si128(dst2);
                    /* pinsrw $1, (%(__int64)a1,%(__int64)ptr,2), %xmm0 */;
                    *(__int64 *)(rsp + v8 + 58) = _mm_cvtsi128_si64(xmm0);
                    ptr2 = (struct Struct_2_t *)v6;
                } while ((ptr2 > 0x98967F));
            }
            if (v6 > 9) {
                v7 = v6;
                v7 >>= 2;
                v7 *= 0x147B;
                v7 >>= 17;
                v8 = v7 * 100;
                v6 -= v8;
                v6 = *(a1 + v6*2);
                *(__int64 *)(rsp + result + 60) = v6;
                result -= 2;
                v6 = v7;
            }
            if (dst3 != 0) {
                if (v6 != 0) {
                    v6 &= 15;
                    a1 = *(a1 + v6*2 + 1);
                    *(__int64 *)(rsp + result + 61) = a1;
                    --result;
                }
                a1 = 10;
                a1 = (int *)((__int64)a1 - (__int64)result);
                result += rsp;
                result += 62;
                v_28 = (int)a1;
                v_20 = (__int64)result;
                return sub_140011970(a2, 1, 1, 0);
            }
            return v_20;
        }
        return v_20;
    }
    return (__int64)result;
}