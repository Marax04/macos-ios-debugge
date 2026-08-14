// inferred from 4 accesses on `a2`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
    char _pad_28[16];
    __int64 field_40; // offset 64
    char _pad_40[64];
    __int64 field_88; // offset 136
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 6 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    char _pad_20[16];
    __int64 field_38; // offset 56
    char _pad_38[64];
    __int64 field_80; // offset 128
    char _pad_80[8];
    __int64 field_90; // offset 144
    char _pad_90[96];
    __int64 field_F8; // offset 248
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_14009D9C0();
__int64 sub_14009F2E1();
__int64 sub_1400F5F90();
__int64 sub_1400F27F0();

__int64 __fastcall sub_14009E4B0(size_t *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int v_28;
    int v_2d0;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    int v_48;
    int v_4d0;
    int v_4e0;
    __int64 v_50;
    __int64 *dst;
    __int64 v9;
    __int64 v8;
    __int64 v12;
    __int64 *result;
    __int64 v10;
    struct Struct_3_t *ptr2;
    __m128i xmm0;
    __m128i xmm1;
    struct Struct_2_t *ptr;
    __int64 *dst2;
    __int64 v11;
    __int64 v6;
    __int64 v7;
    __m128i xmm7;
    __m128i xmm6;

    dst = (__int64 *)a1;
    v9 = a2->field_10;
    v8 = a2->field_28;
    v12 = v9 * 56;
    a1 = a2->field_40;
    result = a2->field_88;
    v10 = v8 + a1;
    v10 += (__int64)result;
    v10 += v12;
    v10 += 136;
    if (!((v10 >= 0))) {
        sub_1400F3360(a1);
    }
    ptr2 = (struct Struct_3_t *)a2;
    v_48 = (int)a1;
    v_50 = (__int64)result;
    if ((0 /* unresolved: flags == */)) {
        v_28 = 0;
        v_30 = 1;
        v_38 = 0;
    } else {
        sub_14002EDF0(0, v10);
        if (result == 0) {
            sub_1400F3326(1, v10);
            _mm_store_si128((__m128i *)&v_4e0, xmm7);
            _mm_store_si128((__m128i *)&v_4d0, xmm6);
            v10 = (__int64)dst2;
            ptr2 = (struct Struct_3_t *)a2;
            dst = (__int64 *)a1;
            a1 = rsp + 720;
            sub_14009D9C0(a1);
            result = (__int64 *)v_2d0;
            a1 = (size_t *)result;
            a1 = (size_t *)(-(__int64)a1);
            if ((0 /* overflow check on (-a1) */)) JUMPOUT(0x14009ebb3);
            *dst = 1;
            return sub_14009F2E1();
        } else {
            v_28 = v10;
            v_30 = (__int64)result;
            v_38 = 0;
            if (v10 <= 7) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, 0, 8);
                result = (__int64 *)v_30;
                v10 = v_38;
            } else {
                v10 = 0;
            }
            a1 = 0x3430343230464E49;
            *(result + v10) = a1;
            v10 += 8;
            v_38 = v10;
            result = (__int64 *)v_28;
            a1 = (size_t *)result;
            a1 -= v10;
            v_40 = (__int64)dst;
            if (a1 <= 3) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 4);
                result = (__int64 *)v_28;
                v10 = v_38;
            }
            a1 = (size_t *)v_30;
            *(a1 + v10) = 4;
            v10 += 4;
            v_38 = v10;
            dst = ptr2->field_90;
            a2 = (struct Struct_1_t *)result;
            a2 -= v10;
            if (a2 <= 7) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 8);
                v10 = v_38;
                result = (__int64 *)v_28;
                a1 = (size_t *)v_30;
            }
            *(a1 + v10) = dst;
            v10 += 8;
            v_38 = v10;
            dst = ptr2 + 152;
            a2 = (struct Struct_1_t *)result;
            a2 -= v10;
            if (a2 <= 31) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 32);
                v10 = v_38;
                result = (__int64 *)v_28;
                a1 = (size_t *)v_30;
            }
            xmm0 = _mm_loadu_si128((__m128i *)dst);
            xmm1 = _mm_loadu_si128((__m128i *)(dst + 16));
            _mm_storeu_si128((__m128i *)(a1 + v10 + 16), xmm1);
            _mm_storeu_si128((__m128i *)(a1 + v10), xmm0);
            v10 += 32;
            v_38 = v10;
            dst = 0xFFFFFFFF;
            if (v9 < dst) dst = v9;
            result -= v10;
            if (result <= 3) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 4);
                a1 = (size_t *)v_30;
                v10 = v_38;
            }
            *(a1 + v10) = dst;
            v10 += 4;
            v_38 = v10;
            if (v9 != 0) {
                v9 = ptr2->field_8;
                v9 += 44;
                dst = 0;
                a1 = rsp + 40;
                do {
                    result = (__int64 *)v_28;
                    a2 = (struct Struct_1_t *)result;
                    a2 -= v10;
                    ptr = (struct Struct_2_t *)a1;
                    sub_1400F5F90(a1, v10, 8);
                    result = (__int64 *)v_28;
                    v10 = v_38;
                    ptr = dst + v9;
                    dst2 = (__int64 *)v_30;
                    a2 = *(__int64 *)(ptr - 12);
                    *(dst2 + v10) = a2;
                    v10 += 8;
                    v_38 = v10;
                    v11 = *(__int64 *)(ptr - 4);
                    a2 = (struct Struct_1_t *)result;
                    a2 -= v10;
                    if (a2 <= 3) {
                        v10 = (__int64)a1;
                        sub_1400F5F90(ptr, v10, 4);
                        v10 = v_38;
                        result = (__int64 *)v_28;
                        dst2 = (__int64 *)v_30;
                    }
                    *(dst2 + v10) = v11;
                    v10 += 4;
                    v_38 = v10;
                    a2 = (struct Struct_1_t *)result;
                    a2 -= v10;
                    if (a2 <= 11) {
                        v10 = (__int64)a1;
                        sub_1400F5F90(v10, v10, 12);
                        v10 = v_38;
                        result = (__int64 *)v_28;
                        dst2 = (__int64 *)v_30;
                    }
                    a2 = ptr->field_8;
                    *(dst2 + v10 + 8) = a2;
                    a2 = ptr->field_0;
                    *(dst2 + v10) = a2;
                    v10 += 12;
                    v_38 = v10;
                    result -= v10;
                    if (result <= 31) {
                        ptr = (struct Struct_2_t *)a1;
                        sub_1400F5F90(v10, v10, 32);
                        a1 = (size_t *)ptr;
                        dst2 = (__int64 *)v_30;
                        v10 = v_38;
                    }
                    result = dst + v9;
                    result -= 44;
                    xmm0 = _mm_loadu_si128((__m128i *)result);
                    xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
                    _mm_storeu_si128((__m128i *)(dst2 + v10 + 16), xmm1);
                    _mm_storeu_si128((__m128i *)(dst2 + v10), xmm0);
                    v10 += 32;
                    v_38 = v10;
                    dst += 56;
                } while (v12 != dst);
            }
            v9 = 0xFFFFFFFF;
            if (v8 < v9) v9 = v8;
            dst = (__int64 *)v_28;
            result = dst;
            result -= v10;
            if (result <= 3) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 4);
                dst = (__int64 *)v_28;
                v10 = v_38;
            }
            ptr = (struct Struct_2_t *)v_30;
            *(__int64 *)(ptr + v10) = (__int64)(v9);
            v10 += 4;
            v_38 = v10;
            a2 = ptr2->field_20;
            result = dst;
            result -= v10;
            if (v8 > result) {
                a1 = rsp + 40;
                dst = (__int64 *)a2;
                sub_1400F5F90(a1, v10, v8);
                a2 = (struct Struct_1_t *)dst;
                v10 = v_38;
                dst = (__int64 *)v_28;
                ptr = (struct Struct_2_t *)v_30;
            }
            v11 = v_48;
            a1 = ptr + v10;
            sub_1400F27F0(a1, a2, v8);
            v10 += v8;
            v_38 = v10;
            v8 = 0xFFFFFFFF;
            if (v11 < v8) v8 = v11;
            dst -= v10;
            if (dst <= 3) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 4);
                ptr = (struct Struct_2_t *)v_30;
                v10 = v_38;
            }
            *(__int64 *)(ptr + v10) = (__int64)(v8);
            v10 += 4;
            v_38 = v10;
            a2 = ptr2->field_38;
            dst = (__int64 *)v_28;
            result = dst;
            result -= v10;
            if (v11 > result) {
                a1 = rsp + 40;
                dst = (__int64 *)a2;
                sub_1400F5F90(a1, v10, v11);
                a2 = (struct Struct_1_t *)dst;
                dst = (__int64 *)v_28;
                v10 = v_38;
            }
            v6 = ptr2 + 184;
            ptr = (struct Struct_2_t *)v_30;
            a1 = ptr + v10;
            sub_1400F27F0(a1, a2, v11);
            v10 += v11;
            v_38 = v10;
            result = dst;
            result -= v10;
            if (result <= 31) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 32);
                v10 = v_38;
                dst = (__int64 *)v_28;
                ptr = (struct Struct_2_t *)v_30;
            }
            xmm0 = _mm_loadu_si128((__m128i *)v6);
            xmm1 = _mm_loadu_si128((__m128i *)(v6 + 16));
            _mm_storeu_si128((__m128i *)(ptr + v10 + 16), xmm1);
            _mm_storeu_si128((__m128i *)(ptr + v10), xmm0);
            v10 += 32;
            v_38 = v10;
            v11 = 0xFFFFFFFF;
            v7 = v_50;
            if (v7 < v11) v11 = v7;
            dst -= v10;
            if (dst <= 3) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 4);
                ptr = (struct Struct_2_t *)v_30;
                v10 = v_38;
            }
            *(__int64 *)(ptr + v10) = (__int64)(v11);
            v10 += 4;
            v_38 = v10;
            a2 = ptr2->field_80;
            dst = (__int64 *)v_28;
            result = dst;
            result -= v10;
            if (v7 > result) {
                a1 = rsp + 40;
                dst = (__int64 *)a2;
                sub_1400F5F90(a1, v10, v7);
                a2 = (struct Struct_1_t *)dst;
                dst = (__int64 *)v_28;
                v10 = v_38;
            }
            v11 = ptr2 + 216;
            ptr = (struct Struct_2_t *)v_30;
            a1 = ptr + v10;
            sub_1400F27F0(a1, a2, v7);
            v10 += v7;
            v_38 = v10;
            result = dst;
            result -= v10;
            if (result <= 31) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 32);
                v10 = v_38;
                dst = (__int64 *)v_28;
                ptr = (struct Struct_2_t *)v_30;
            }
            xmm0 = _mm_loadu_si128((__m128i *)v11);
            xmm1 = _mm_loadu_si128((__m128i *)(v11 + 16));
            _mm_storeu_si128((__m128i *)(ptr + v10 + 16), xmm1);
            _mm_storeu_si128((__m128i *)(ptr + v10), xmm0);
            v10 += 32;
            v_38 = v10;
            ptr2 = ptr2->field_F8;
            dst -= v10;
            if (dst <= 3) {
                a1 = rsp + 40;
                sub_1400F5F90(a1, v10, 4);
                ptr = (struct Struct_2_t *)v_30;
                v10 = v_38;
            }
            result = (__int64 *)v_40;
            *(__int64 *)(ptr + v10) = (__int64)(ptr2);
            v10 += 4;
            v_38 = v10;
            *(result + 16) = v10;
            xmm0 = _mm_loadu_si128((__m128i *)&v_28);
            _mm_storeu_si128((__m128i *)result, xmm0);
            return _mm_cvtsi128_si64(xmm0);
        }
    }
    return (__int64)result;
}