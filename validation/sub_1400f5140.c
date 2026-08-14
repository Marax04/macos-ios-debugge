// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[120];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
    char _pad_88[2064];
    __int64 field_8A0; // offset 0x8A0
    __int64 field_8A8; // offset 0x8A8
    char _pad_8A8[80];
    __int64 field_900; // offset 0x900
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[2072];
    __int64 field_818; // offset 0x818
    __int64 field_820; // offset 0x820
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr4`
struct Struct_4_t {
    __int64 field_0; // offset 0
    char _pad_0[504];
    __int64 field_200; // offset 512
};

__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_14002DFB0();
__int64 sub_1400F4200();
extern __int64 off_14012D008;
extern __int64 off_14012D000;
extern __int64 off_140110058;
extern __int64 off_140110048;
extern __int64 off_1400203D0;

__int64 __fastcall sub_1400F5140(__int64 *a1) {
    __int64 rsp;
    struct Struct_3_t *ptr3;
    __int64 result;
    struct Struct_4_t *ptr4;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v6;
    struct Struct_1_t *ptr;
    __int64 *dst;
    __int64 v9;
    __int64 v3;
    __int64 v7;
    struct Struct_2_t *ptr2;
    __int64 v8;

    ptr3 = (struct Struct_3_t *)a1;
    result = *(a1 + 8);
    if (result == 0) {
        result = off_14012D008;
        if (result != 0) JUMPOUT(0x1400f52da);
        ptr4 = off_14012D000;
        *(__int64 *)ptr4 = (__int64)(ptr4->field_0 + 1);
        if ((ptr4->field_0 <= 0)) JUMPOUT(0x1400f52f0);
        result = 96;
        xmm0 = _mm_loadu_si128((__m128i *)&off_140110058);
        xmm1 = _mm_loadu_si128((__m128i *)&off_140110048);
        do {
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v6 - 48), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v6 - 64), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v6 - 32), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v6 - 16), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v6), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v6 + 16), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v6 + 32), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + v6 + 48), xmm0);
            v6 += 128;
        } while (v6 != 0x860);
        sub_14002EDF0(0, 0x980);
        if (v6 == 0) JUMPOUT(0x1400f530a);
        ptr = (struct Struct_1_t *)v6;
        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & -128);
        dst = ptr + 128;
        ptr->field_78 = v6;
        ptr->field_80 = 0;
        ptr->field_88 = ptr4;
        v9 = ptr + 144;
        v3 = rsp + 32;
        sub_1400F27F0(v9, v3, 0x800);
        xmm0 = _mm_setzero_si128();
        _mm_store_si128((__m128i *)(ptr + 0x890), xmm0);
        ptr->field_8A0 = 1;
        ptr->field_8A8 = 0;
        ptr->field_900 = 0;
        v7 = ptr4->field_200;
        ptr->field_80 = v7;
        /* cmpxchg %(__int64)dst, 512(%(__int64)ptr4) */;
        if (!((0 /* unresolved: flags == */))) {
            do {
                *dst = v7;
                /* cmpxchg %(__int64)dst, 512(%(__int64)ptr4) */;
            } while ((0 /* unresolved: flags != */));
        }
        result = ptr3->field_8;
        ptr2 = ptr3->field_0;
        *(__int64 *)ptr3 = (__int64)(dst);
        ptr3->field_8 = 1;
        if (result != 1) {
            if (result != 0) JUMPOUT(0x1400f52f2);
            v3 = &off_1400203D0;
            sub_14002DFB0(ptr3, v3);
        } else {
            v8 = ptr2->field_820;
            v3 = v8 - 1;
            ptr2->field_820 = v3;
            v8 ^= 1;
            v8 |= ptr2->field_818;
            if (!((v8 != 0))) {
                sub_1400F4200(ptr2, v3);
            }
        }
    } else {
        if (result != 1) {
            ptr3 = 0;
        }
    }
    result = (__int64)ptr3;
    return result;
}