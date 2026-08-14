// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    __int16 field_0; // offset 0
    __int64 field_2; // offset 2
};

// inferred from 2 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_4_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14007B540();
__int64 sub_1400F87E0();
extern __int64 off_1401190A3;

__int64 __fastcall sub_14007B9B0(struct Struct_1_t *a1,struct Struct_2_t *a2, __int64 a3, int a4) {
    __int64 *result;
    __int64 v8;
    __int64 v2;
    __int64 i;
    __m128i xmm0;
    __int64 v4;
    struct Struct_3_t *ptr;
    struct Struct_4_t *ptr2;
    __int64 i2;
    __int64 v10;
    __int64 v5;

    result = a2->field_0;
    if (result == 0) {
        result = a2->field_2;
        result = (__int64 *)((__int64)(__int64)result & 7);
        v8 = &off_1401190A3;
        v2 = *(result + v8);
        i = ((__int64 *)a1)[2];
        if (i == a1->field_0) JUMPOUT(0x14007ba90);
        result = a1->field_8;
        a2 = i + i*2;
        a2 = (struct Struct_2_t *)((__int64)(__int64)a2 << 4);
        *(__int64 *)((__int64)result + (__int64)a2) = a4;
        xmm0 = _mm_loadu_si128((__m128i *)a3);
        _mm_storeu_si128((__m128i *)((__int64)result + (__int64)a2 + 8), xmm0);
        *(__int64 *)((__int64)result + (__int64)a2 + 24) = v2;
        ++i;
        ((__int64 *)a1)[2] = (__int64)(i);
    } else {
        if (result == 1) {
            v2 = a4;
            v4 = a3;
            a2 += 4;
            ptr = (struct Struct_3_t *)a1;
            sub_14007B540(a1, a2);
            ptr2 = (struct Struct_4_t *)ptr;
            i2 = ptr->field_10;
            if (i2 == ptr->field_0) {
                v10 = (__int64)result;
                sub_1400F87E0(ptr, a2, a3, 0x8000000000000000);
                result = (__int64 *)v10;
                ptr2 = (struct Struct_4_t *)ptr;
            }
            a2 = ptr2->field_8;
            v2 = i2 + i2*2;
            v2 <<= 4;
            v5 = 0x8000000000000005;
            *(__int64 *)(a2 + v2) = (__int64)(v5);
            xmm0 = _mm_loadu_si128((__m128i *)v4);
            _mm_storeu_si128((__m128i *)(a2 + v2 + 8), xmm0);
            *(__int64 *)(a2 + v2 + 24) = (__int64)(result);
            *(__int64 *)(a2 + v2 + 28) = (__int64)(7);
            *(__int64 *)(a2 + v2 + 29) = (__int64)(v2);
            ++i2;
            ptr2->field_10 = i2;
        }
    }
    return (__int64)result;
}