// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 7 accesses on `i`
struct Struct_4_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    int field_18; // offset 24
    int field_1C; // offset 28
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
__int64 sub_1400F1505();
extern __int64 off_14011D8B0;
extern __int64 off_14011D898;
extern __int64 off_14011D858;
extern __int64 off_14011D880;

__int64 __fastcall sub_1400F1290(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    int v_2c;
    int v_30;
    __int64 v_40;
    int v_50;
    int v_60;
    struct Struct_3_t *ptr;
    struct Struct_4_t *i;
    __int64 *dst;
    __int64 v10;
    __int64 *dst2;
    __int64 v13;
    __int64 *result;
    __int64 v11;
    __m128i xmm0;
    __int64 v9;
    __int64 v5;
    __int64 v7;
    __int64 v6;
    __int64 *dst3;

    ptr = (struct Struct_3_t *)a2;
    i = (struct Struct_4_t *)a1;
    dst = a2->field_0;
    v10 = *(dst + 362);
    sub_14002EDF0(0, 464);
    if (result != 0) {
        dst2 = result;
        *result = 0;
        v13 = ptr->field_10;
        result = *(dst + 362);
        v11 = v13;
        v11 = ~v11;
        v11 += (__int64)result;
        *(dst2 + 362) = v11;
        result =  + v13*2;
        result += v13;
        a1 = *(dst + (__int64)(__int64)result*8 + 24);
        v_60 = (int)a1;
        xmm0 = _mm_loadu_si128((__m128i *)(dst + (__int64)(__int64)result*8 + 8));
        _mm_store_si128((__m128i *)&v_50, xmm0);
        if (v11 < 12) {
            result = dst + 8;
            a1 = *(dst + v13*8 + 276);
            v_2c = (int)a1;
            v9 = *(dst + v13*8 + 272);
            a1 = dst2 + 8;
            a2 =  + v13*2 + 3;
            a2 += v13;
            a2 = result + (__int64)(__int64)a2*8;
            v11 <<= 3;
            v5 = v11 + v11*2;
            sub_1400F27F0(a1, a2, v5);
            a1 = dst2 + 272;
            a2 = dst + v13*8;
            a2 += 280;
            sub_1400F27F0(a1, a2, v11);
            *(dst + 362) = v13;
            xmm0 = _mm_load_si128((__m128i *)&v_50);
            _mm_store_si128((__m128i *)&v_30, xmm0);
            result = (__int64 *)v_60;
            v_40 = (__int64)result;
            v11 = *(dst2 + 362);
            v7 = v11 + 1;
            if (v11 >= 12) {
                v6 = &off_14011D8B0;
                sub_1400F3600(0, v7, 12, v6);
                sub_1400F3340(8, 464);
                v6 = &off_14011D898;
                sub_1400F3600(0, v11, 11, v6);
            } else {
                v10 -= v13;
                if (v10 == v7) {
                    a1 = (struct Struct_1_t *)dst2;
                    a1 += 368;
                    a2 = dst + v13*8;
                    a2 += 376;
                    v5 <<= 3;
                    sub_1400F27F0(a1, a2, v7);
                    result = ptr->field_8;
                    a1 = 0;
                    a2 = (struct Struct_2_t *)a1;
                    a1 += 0;
                    dst3 = *(dst2 + (__int64)(__int64)a2*8 + 368);
                    *dst3 = dst2;
                    *(dst3 + 360) = a2;
                    while (a2 < v11) {
                    }
                    a1 = (struct Struct_1_t *)v_40;
                    i->field_10 = a1;
                    xmm0 = _mm_load_si128((__m128i *)&v_30);
                    _mm_storeu_si128((__m128i *)i, xmm0);
                    i->field_20 = dst;
                    i->field_28 = result;
                    i->field_18 = v9;
                    a1 = (struct Struct_1_t *)v_2c;
                    i->field_1C = a1;
                    i->field_30 = dst2;
                    i->field_38 = result;
                    return (__int64)a1;
                }
            }
            a1 = &off_14011D858;
            v9 = &off_14011D880;
            sub_1400F37D0(a1, 40, v9);
            result = a1->field_0;
            i = ((__int64 *)a1)[2];
            if (a2->field_0 != 1) JUMPOUT(0x1400f14d3);
            ptr = a2->field_8;
            v13 = ((__int64 *)a1)[15];
            if (i == result) JUMPOUT(0x1400f1512);
            a2 = a1->field_8;
            *(__int64 *)((__int64)a2 + (__int64)i) = v13;
            ++i;
            ((__int64 *)a1)[2] = (__int64)(i);
            result = (__int64 *)((__int64)result - (__int64)i);
            if (result <= 7) JUMPOUT(0x1400f1543);
            *(__int64 *)((__int64)a2 + (__int64)i) = ptr;
            i += 8;
            return sub_1400F1505();
        }
        return (__int64)i;
    }
    return (__int64)result;
}