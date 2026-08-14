// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 7 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    int field_18; // offset 24
    int field_1C; // offset 28
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[274];
    __int64 field_112; // offset 274
    char _pad_112[80];
    __int64 field_16A; // offset 362
};

// inferred from 2 accesses on `ptr4`
struct Struct_4_t {
    char _pad_start[272];
    __int64 field_110; // offset 272
    char _pad_110[80];
    __int64 field_168; // offset 360
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

__int64 __fastcall sub_1400F1090(int *a1, int *a2) {
    int v_20;
    int v_2c;
    __int64 v_30;
    __int64 v_40;
    int v_50;
    int v_60;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 v9;
    struct Struct_3_t *ptr3;
    __int64 v10;
    __int64 *result;
    __int64 v11;
    __m128i xmm0;
    __int64 v13;
    struct Struct_4_t *ptr4;
    __int64 v6;
    __int64 *dst2;
    __int64 v7;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    dst = *a2;
    v9 = *(dst + 274);
    sub_14002EDF0(0, 384);
    if (result != 0) {
        ptr3 = (struct Struct_3_t *)result;
        *result = 0;
        v10 = ptr->field_10;
        result = *(dst + 274);
        v11 = v10;
        v11 = ~v11;
        v11 += (__int64)result;
        ptr3->field_112 = v11;
        result =  + v10*2;
        result += v10;
        a1 = *(dst + (__int64)(__int64)result*8 + 24);
        v_50 = (int)a1;
        xmm0 = _mm_loadu_si128((__m128i *)(dst + (__int64)(__int64)result*8 + 8));
        _mm_store_si128((__m128i *)&v_40, xmm0);
        if (v11 < 12) {
            result = dst + 8;
            v13 = *(dst + v10 + 276);
            a1 = ptr3 + 8;
            a2 =  + v10*2 + 3;
            a2 += v10;
            a2 = result + (__int64)(__int64)a2*8;
            result =  + v11*8;
            ptr4 = result + (__int64)(__int64)result*2;
            sub_1400F27F0(a1, a2, ptr4);
            a1 = ptr3 + 276;
            a2 = dst + v10;
            a2 += 277;
            sub_1400F27F0(a1, a2, v11);
            *(dst + 274) = v10;
            xmm0 = _mm_load_si128((__m128i *)&v_40);
            _mm_store_si128((__m128i *)&v_20, xmm0);
            result = (__int64 *)v_50;
            v_30 = (__int64)result;
            v11 = ptr3->field_112;
            ptr4 = v11 + 1;
            if (v11 >= 12) {
                v6 = &off_14011D8B0;
                sub_1400F3600(0, ptr4, 12, v6);
                sub_1400F3340(8, 384);
                v6 = &off_14011D898;
                sub_1400F3600(0, v11, 11, v6);
            } else {
                v9 -= v10;
                if (v9 == ptr4) {
                    a1 = (int *)ptr3;
                    a1 += 288;
                    a2 = dst + v10*8;
                    a2 += 296;
                    ptr4 = (struct Struct_4_t *)((__int64)(__int64)ptr4 << 3);
                    sub_1400F27F0(a1, a2, ptr4);
                    result = ptr->field_8;
                    a1 = 0;
                    a2 = a1;
                    a1 += 0;
                    ptr4 = *(__int64 *)(ptr3 + (__int64)(__int64)a2*8 + 288);
                    *(__int64 *)ptr4 = (__int64)(ptr3);
                    ptr4->field_110 = a2;
                    while (a2 < v11) {
                    }
                    a1 = (int *)v_30;
                    ptr2->field_10 = a1;
                    xmm0 = _mm_load_si128((__m128i *)&v_20);
                    _mm_storeu_si128((__m128i *)ptr2, xmm0);
                    ptr2->field_20 = dst;
                    ptr2->field_28 = result;
                    ptr2->field_18 = v13;
                    ptr2->field_30 = ptr3;
                    ptr2->field_38 = result;
                    return _mm_cvtsi128_si64(xmm0);
                }
            }
            a1 = &off_14011D858;
            ptr4 = &off_14011D880;
            sub_1400F37D0(a1, 40, ptr4);
            ptr = (struct Struct_1_t *)a2;
            ptr2 = (struct Struct_2_t *)a1;
            dst2 = *a2;
            v10 = *(dst2 + 362);
            sub_14002EDF0(0, 464);
            if (result == 0) JUMPOUT(0x1400f144b);
            ptr3 = (struct Struct_3_t *)result;
            *result = 0;
            v13 = ptr->field_10;
            result = *(dst2 + 362);
            v7 = v13;
            v7 = ~v7;
            v7 += (__int64)result;
            ptr3->field_16A = v11;
            result =  + v13*2;
            result += v13;
            a1 = *(dst2 + (__int64)(__int64)result*8 + 24);
            v_60 = (int)a1;
            xmm0 = _mm_loadu_si128((__m128i *)(dst2 + (__int64)(__int64)result*8 + 8));
            _mm_store_si128((__m128i *)&v_50, xmm0);
            if (v7 >= 12) JUMPOUT(0x1400f145a);
            result = dst2 + 8;
            a1 = *(dst2 + v13*8 + 276);
            v_2c = (int)a1;
            v9 = *(dst2 + v13*8 + 272);
            a1 = ptr3 + 8;
            a2 =  + v13*2 + 3;
            a2 += v13;
            a2 = result + (__int64)(__int64)a2*8;
            v7 <<= 3;
            ptr4 = v7 + v7*2;
            sub_1400F27F0(a1, a2, ptr4);
            a1 = ptr3 + 272;
            a2 = dst2 + v13*8;
            a2 += 280;
            sub_1400F27F0(a1, a2, v7);
            *(dst2 + 362) = v13;
            xmm0 = _mm_load_si128((__m128i *)&v_50);
            _mm_store_si128((__m128i *)&v_30, xmm0);
            result = (__int64 *)v_60;
            v_40 = (__int64)result;
            v11 = ptr3->field_16A;
            ptr4 = v7 + 1;
            if (v7 >= 12) JUMPOUT(0x1400f1434);
            v10 -= v13;
            if (v10 != ptr4) JUMPOUT(0x1400f1471);
            a1 = (int *)ptr3;
            a1 += 368;
            a2 = dst2 + v13*8;
            a2 += 376;
            ptr4 = (struct Struct_4_t *)((__int64)(__int64)ptr4 << 3);
            sub_1400F27F0(a1, a2, ptr4);
            result = ptr->field_8;
            a1 = 0;
            a2 = a1;
            a1 += 0;
            ptr4 = *(__int64 *)(ptr3 + (__int64)(__int64)a2*8 + 368);
            *(__int64 *)ptr4 = (__int64)(ptr3);
            ptr4->field_168 = a2;
            while (a2 < v7) {
            }
            a1 = (int *)v_40;
            ptr2->field_10 = a1;
            xmm0 = _mm_load_si128((__m128i *)&v_30);
            _mm_storeu_si128((__m128i *)ptr2, xmm0);
            ptr2->field_20 = dst2;
            ptr2->field_28 = result;
            ptr2->field_18 = v9;
            a1 = (int *)v_2c;
            ptr2->field_1C = a1;
            ptr2->field_30 = ptr3;
            ptr2->field_38 = result;
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return (__int64)result;
}