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

// inferred from 2 accesses on `a3`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_4_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[64];
    __int64 field_50; // offset 80
};

// inferred from 6 accesses on `ptr2`
struct Struct_5_t {
    char _pad_start[8];
    int field_8; // offset 8
    int field_C; // offset 12
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[24];
    __int64 field_38; // offset 56
    char _pad_38[16];
    __int64 field_50; // offset 80
};

// inferred from 8 accesses on `ptr3`
struct Struct_6_t {
    __int64 field_0; // offset 0
    int field_8; // offset 8
    int field_C; // offset 12
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[24];
    __int64 field_38; // offset 56
    char _pad_38[12];
    int field_4C; // offset 76
    __int64 field_50; // offset 80
};

// inferred from 2 accesses on `i`
struct Struct_7_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140073070();
__int64 sub_1400F27F0();
__int64 sub_140072CF0();
__int64 sub_140071090();
extern __int64 off_14011EB28;
extern __int64 off_14011EB58;
extern __int64 off_14011EB70;
extern __int64 off_14011E9F0;
extern __int64 off_14011E9D8;
extern __int64 off_14011E9C0;
extern __int64 off_14011E990;
extern __int64 off_14011E978;
extern __int64 off_14011E960;
extern __int64 off_14011EA50;
extern __int64 off_14011EA38;
extern __int64 off_14011EA20;
extern __int64 off_14011EB40;
extern __int64 off_14011EB10;
extern __int64 off_14011EAF8;
extern __int64 off_14011EAE0;
extern __int64 off_14011EAC8;
extern __int64 off_14011EAB0;
extern __int64 off_14011EA98;
extern __int64 off_14011EA80;
extern __int64 off_14011EA68;

__int64 __fastcall sub_1400719A0(struct Struct_1_t *a1,struct Struct_2_t *a2,struct Struct_3_t *a3, size_t *a4) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int arg_20;
    int arg_30;
    int arg_38;
    int arg_40;
    int arg_4c;
    __int64 arg_50;
    int arg_8;
    __int64 arg_c;
    __int64 v_100;
    int v_170;
    int v_178;
    int v_18;
    __int64 v_20;
    __int64 v_28;
    __int64 v_38;
    __int64 v_40;
    __int64 v_48;
    __int64 v_50;
    __int64 v_58;
    __int64 v_60;
    int v_68;
    __int64 v_70;
    __int64 v_78;
    int v_8;
    int v_80;
    __int64 v_90;
    int v_a8;
    int v_b0;
    int v_bc;
    int v_c0;
    int v_d0;
    int v_e0;
    int v_f0;
    __int64 *v_0;
    struct Struct_4_t *ptr;
    __int64 *v2;
    struct Struct_5_t *ptr2;
    struct Struct_7_t *i;
    struct Struct_6_t *ptr3;
    __int64 *result;
    __int64 *dst;
    __int64 *src;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;
    __m128i xmm3;
    __int64 *src2;
    __int64 *dst2;
    __int64 *dst3;
    __m128i xmm4;

    ptr = (struct Struct_4_t *)a3;
    v2 = (__int64 *)a2;
    if (a2 >= 33) {
        ptr2 = (struct Struct_5_t *)a4;
        i = (struct Struct_7_t *)v_178;
        ptr3 = (struct Struct_6_t *)v_170;
        result = ptr - 88;
        v_60 = (__int64)result;
        dst = 2;
        src = 0;
        v_50 = (__int64)a4;
        do {
            result = v2;
            v_38 = (__int64)a1;
            v_70 = (__int64)i;
            --ptr3;
            while (!((ptr3 < 0))) {
                a4 = (size_t *)result;
                a4 = (size_t *)((__int64)(__int64)a4 >> 3);
                a2 = (__int64)(__int64)a4 * 352;
                a2 = (struct Struct_2_t *)((__int64)a2 + (__int64)a1);
                a3 = (__int64)(__int64)a4 * 616;
                a3 = (struct Struct_3_t *)((__int64)a3 + (__int64)a1);
                v_40 = (__int64)result;
                v_58 = (__int64)ptr3;
                if (result >= 64) {
                    sub_140073070(a1, a2, a3, a4);
                    a1 = (struct Struct_1_t *)v_38;
                    ptr3 = (struct Struct_6_t *)result;
                    a4 = (size_t *)ptr3;
                    a4 = (size_t *)((__int64)a4 - (__int64)a1);
                    a4 = (size_t *)((__int64)(__int64)a4 >> 3);
                    result = 0x2E8BA2E8BA2E8BA3;
                    a4 = (size_t *)((__int64)(__int64)(__int64)a4 * (__int64)result);
                    result = ptr3->field_50;
                    v_100 = (__int64)result;
                    xmm0 = _mm_loadu_si128((__m128i *)(ptr3 + 64));
                    _mm_store_si128((__m128i *)&v_f0, xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)ptr3);
                    xmm1 = _mm_loadu_si128((__m128i *)(ptr3 + 16));
                    xmm2 = _mm_loadu_si128((__m128i *)(ptr3 + 32));
                    xmm3 = _mm_loadu_si128((__m128i *)(ptr3 + 48));
                    _mm_store_si128((__m128i *)&v_e0, xmm3);
                    _mm_store_si128((__m128i *)&v_d0, xmm2);
                    _mm_store_si128((__m128i *)&v_c0, xmm1);
                    _mm_store_si128((__m128i *)&v_b0, xmm0);
                    src2 = (__int64 *)v_40;
                    if (i == 0) {
                        if (ptr2 < src2) JUMPOUT(0x140072c8a);
                        ptr2 = (__int64)(__int64)src2 * 88;
                        dst2 = (__int64)ptr + (__int64)ptr2;
                        v2 = 0;
                        result = (__int64 *)a1;
                        i = (struct Struct_7_t *)dst2;
                        v_68 = (int)a4;
                        a2 = (struct Struct_2_t *)a4;
                        do {
                            a3 = (__int64)(__int64)a2 * 88;
                            a3 = (struct Struct_3_t *)((__int64)a3 + (__int64)a1);
                            a1 = &off_14011EB28;
                            do {
                                a4 = 80;
                                src2 = 80;
                                if (!__OFSUB(src, ptr3->field_0)) {
                                    src2 = *(__int64 *)((__int64)result + (__int64)src2);
                                    i -= 88;
                                    dst3 = (__int64)(__int64)v2 * 88;
                                    a4 = (size_t *)i;
                                    if (src2 < *(__int64 *)((__int64)ptr3 + (__int64)a4)) i = ptr;
                                    src2 = (__int64 *)arg_50;
                                    *(__int64 *)((__int64)i + (__int64)dst3 + 80) = src2;
                                    xmm0 = _mm_loadu_si128((__m128i *)(result + 64));
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)dst3 + 64), xmm0);
                                    xmm0 = _mm_loadu_si128((__m128i *)result);
                                    xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
                                    xmm2 = _mm_loadu_si128((__m128i *)(result + 32));
                                    xmm3 = _mm_loadu_si128((__m128i *)(result + 48));
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)dst3 + 48), xmm3);
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)dst3 + 32), xmm2);
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)dst3 + 16), xmm1);
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)dst3), xmm0);
                                    v2 += 0;
                                    result += 88;
                                    a4 = (size_t *)v_40;
                                    if (a2 == a4) {
                                        a3 = (__int64)(__int64)v2 * 88;
                                        i = (struct Struct_7_t *)v_38;
                                        v_48 = (__int64)a3;
                                        sub_1400F27F0(i, ptr, a3, a4);
                                        src2 = (__int64 *)v_40;
                                        a1 = (struct Struct_1_t *)i;
                                        a2 = (struct Struct_2_t *)src2;
                                        a2 = (struct Struct_2_t *)((__int64)a2 - (__int64)v2);
                                        if ((a2 == 0)) {
                                            i = (struct Struct_7_t *)v_70;
                                            ptr2 = (struct Struct_5_t *)v_50;
                                            a4 = (size_t *)v_68;
                                            if (v2 == 0) {
                                                if (ptr2 < src2) JUMPOUT(0x140072c8a);
                                                result = (__int64)(__int64)src2 * 88;
                                                v_48 = (__int64)result;
                                                dst3 = (__int64)ptr + (__int64)result;
                                                i = 0;
                                                result = (__int64 *)a1;
                                                v_38 = (__int64)dst3;
                                                dst2 = &off_14011EB58;
                                                v2 = &off_14011EB70;
                                                do {
                                                    ptr2 = (struct Struct_5_t *)a4;
                                                    a2 = (__int64)(__int64)a4 * 88;
                                                    a2 = (struct Struct_2_t *)((__int64)a2 + (__int64)a1);
                                                    while (result < a2) {
                                                        a3 = 80;
                                                        a4 = 80;
                                                        if (!__OFSUB(src, ptr3->field_0)) {
                                                            if (!__OFSUB(src, *result)) {
                                                                a4 = *(__int64 *)((__int64)ptr3 + (__int64)a4);
                                                                dst3 -= 88;
                                                                src2 = (__int64)(__int64)i * 88;
                                                                a3 = (struct Struct_3_t *)dst3;
                                                                if (a4 >= *(__int64 *)((__int64)result + (__int64)a3)) dst3 = ptr;
                                                                a4 = (size_t *)arg_50;
                                                                *(__int64 *)((__int64)dst3 + (__int64)src2 + 80) = a4;
                                                                xmm0 = _mm_loadu_si128((__m128i *)(result + 64));
                                                                _mm_storeu_si128((__m128i *)((__int64)dst3 + (__int64)src2 + 64), xmm0);
                                                                xmm0 = _mm_loadu_si128((__m128i *)result);
                                                                xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
                                                                xmm2 = _mm_loadu_si128((__m128i *)(result + 32));
                                                                xmm3 = _mm_loadu_si128((__m128i *)(result + 48));
                                                                _mm_storeu_si128((__m128i *)((__int64)dst3 + (__int64)src2 + 48), xmm3);
                                                                _mm_storeu_si128((__m128i *)((__int64)dst3 + (__int64)src2 + 32), xmm2);
                                                                _mm_storeu_si128((__m128i *)((__int64)dst3 + (__int64)src2 + 16), xmm1);
                                                                _mm_storeu_si128((__m128i *)((__int64)dst3 + (__int64)src2), xmm0);
                                                                i += 1;
                                                                result += 88;
                                                            }
                                                            a3 = (struct Struct_3_t *)arg_8;
                                                            src2 = a3 - 3;
                                                            if (a3 < 3) src2 = dst;
                                                            a3 = v2[(__int64)src2];
                                                            return (__int64)a3;
                                                        }
                                                        a4 = ptr3->field_8;
                                                        src2 = a4 - 3;
                                                        if (a4 < 3) src2 = dst;
                                                        a4 = v_0[(__int64)src2];
                                                        return (__int64)a4;
                                                    }
                                                    a4 = (size_t *)v_40;
                                                    if (ptr2 == a4) {
                                                        ptr3 = (__int64)(__int64)i * 88;
                                                        dst2 = (__int64 *)a1;
                                                        sub_1400F27F0(a1, ptr, ptr3, a4);
                                                        a1 = (struct Struct_1_t *)v_40;
                                                        v2 = (__int64 *)a1;
                                                        v2 = (__int64 *)((__int64)v2 - (__int64)i);
                                                        if (!((v2 == 0))) {
                                                            dst2 = (__int64 *)((__int64)dst2 + (__int64)ptr3);
                                                            result = i + 1;
                                                            if ((a1 != result)) {
                                                                result = v2;
                                                                result = (__int64 *)((__int64)(__int64)result & -2);
                                                                dst2 = (__int64 *)v_48;
                                                                dst2 += v_60;
                                                                a4 = (size_t *)a1;
                                                                a3 = 0;
                                                                ptr3 = (struct Struct_6_t *)v_58;
                                                                src2 = 0x1FFFFFFFFFFFFFFE;
                                                                dst3 = (__int64 *)v_38;
                                                                do {
                                                                    a2 = (struct Struct_2_t *)arg_50;
                                                                    a4[10] = a2;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)(dst2 + 64));
                                                                    _mm_storeu_si128((__m128i *)(a4 + 64), xmm0);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)dst2);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(dst2 + 16));
                                                                    xmm2 = _mm_loadu_si128((__m128i *)(dst2 + 32));
                                                                    xmm3 = _mm_loadu_si128((__m128i *)(dst2 + 48));
                                                                    _mm_storeu_si128((__m128i *)(a4 + 48), xmm3);
                                                                    _mm_storeu_si128((__m128i *)(a4 + 32), xmm2);
                                                                    _mm_storeu_si128((__m128i *)(a4 + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)a4, xmm0);
                                                                    a2 = a3 + 2;
                                                                    a3 = (struct Struct_3_t *)((__int64)(__int64)a3 ^ (__int64)src2);
                                                                    a3 = (struct Struct_3_t *)((__int64)(__int64)(__int64)a3 * 88);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3));
                                                                    xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3 + 16));
                                                                    xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3 + 32));
                                                                    xmm3 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3 + 48));
                                                                    _mm_storeu_si128((__m128i *)(a4 + 88), xmm0);
                                                                    _mm_storeu_si128((__m128i *)(a4 + 104), xmm1);
                                                                    _mm_storeu_si128((__m128i *)(a4 + 120), xmm2);
                                                                    _mm_storeu_si128((__m128i *)(a4 + 136), xmm3);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3 + 64));
                                                                    _mm_storeu_si128((__m128i *)(a4 + 152), xmm0);
                                                                    a3 = *(__int64 *)((__int64)dst3 + (__int64)a3 + 80);
                                                                    a4[21] = a3;
                                                                    a4 += 176;
                                                                    dst2 -= 176;
                                                                    a3 = (struct Struct_3_t *)a2;
                                                                } while (result != a2);
                                                                if (((__int64)v2 & 1) == 0) {
                                                                    a2 = (struct Struct_2_t *)v_40;
                                                                    if (a2 < i) JUMPOUT(0x140072cd7);
                                                                    i = 0;
                                                                    ptr2 = (struct Struct_5_t *)v_50;
                                                                    if (v2 >= 2) {
                                                                        dst2 = v2;
                                                                        dst2 = (__int64 *)((__int64)(__int64)dst2 >> 1);
                                                                        dst = (__int64)(__int64)dst2 * 88;
                                                                        ptr2 = (__int64)a1 + (__int64)dst;
                                                                        dst = (__int64 *)((__int64)dst + (__int64)ptr);
                                                                        v_38 = (__int64)a1;
                                                                        v_78 = (__int64)ptr2;
                                                                        if (v2 < 8) {
                                                                            result = ((__int64 *)a1)[10];
                                                                            ptr->field_50 = result;
                                                                            xmm0 = _mm_loadu_si128((__m128i *)(a1 + 64));
                                                                            _mm_storeu_si128((__m128i *)(ptr + 64), xmm0);
                                                                            xmm0 = _mm_loadu_si128((__m128i *)a1);
                                                                            xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
                                                                            xmm2 = _mm_loadu_si128((__m128i *)(a1 + 32));
                                                                            xmm3 = _mm_loadu_si128((__m128i *)(a1 + 48));
                                                                            _mm_storeu_si128((__m128i *)(ptr + 48), xmm3);
                                                                            _mm_storeu_si128((__m128i *)(ptr + 32), xmm2);
                                                                            _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
                                                                            _mm_storeu_si128((__m128i *)ptr, xmm0);
                                                                            result = ptr2->field_50;
                                                                            *(dst + 80) = result;
                                                                            xmm0 = _mm_loadu_si128((__m128i *)(ptr2 + 64));
                                                                            _mm_storeu_si128((__m128i *)(dst + 64), xmm0);
                                                                            xmm0 = _mm_loadu_si128((__m128i *)ptr2);
                                                                            xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + 16));
                                                                            xmm2 = _mm_loadu_si128((__m128i *)(ptr2 + 32));
                                                                            xmm3 = _mm_loadu_si128((__m128i *)(ptr2 + 48));
                                                                            _mm_storeu_si128((__m128i *)(dst + 48), xmm3);
                                                                            _mm_storeu_si128((__m128i *)(dst + 32), xmm2);
                                                                            _mm_storeu_si128((__m128i *)(dst + 16), xmm1);
                                                                            _mm_storeu_si128((__m128i *)dst, xmm0);
                                                                            result = 1;
                                                                        } else {
                                                                            sub_140072CF0(a1, ptr);
                                                                            sub_140072CF0(ptr2, dst);
                                                                            a1 = (struct Struct_1_t *)v_38;
                                                                            result = 4;
                                                                        }
                                                                        a2 = (struct Struct_2_t *)v2;
                                                                        a2 = (struct Struct_2_t *)((__int64)a2 - (__int64)dst2);
                                                                        v_68 = (int)a2;
                                                                        v_58 = (__int64)dst2;
                                                                        v_48 = (__int64)result;
                                                                        if (result < dst2) {
                                                                            a3 = (struct Struct_3_t *)v_48;
                                                                            a4 = a3 + 1;
                                                                            result = (__int64)(__int64)a3 * 88;
                                                                            a2 = (__int64)ptr + (__int64)result;
                                                                            ptr2 = 88;
                                                                            ptr2 = (struct Struct_5_t *)((__int64)ptr2 - (__int64)result);
                                                                            i = 2;
                                                                            result = (__int64 *)a3;
                                                                            do {
                                                                                a3 = (__int64)(__int64)result * 88;
                                                                                result = (__int64 *)a4;
                                                                                src = (__int64)ptr + (__int64)a3;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a3));
                                                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 16));
                                                                                xmm2 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 32));
                                                                                xmm3 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 48));
                                                                                _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a3), xmm0);
                                                                                a4 = *(__int64 *)((__int64)a1 + (__int64)a3 + 80);
                                                                                *(__int64 *)((__int64)ptr + (__int64)a3 + 80) = a4;
                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)a1 + (__int64)a3 + 64));
                                                                                _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a3 + 64), xmm0);
                                                                                _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a3 + 48), xmm3);
                                                                                _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a3 + 32), xmm2);
                                                                                _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a3 + 16), xmm1);
                                                                                dst2 = *(__int64 *)((__int64)ptr + (__int64)a3);
                                                                                a4 = 80;
                                                                                src2 = dst2;
                                                                                src2 = (__int64 *)(-(__int64)src2);
                                                                                src2 = 80;
                                                                                src2 = *(__int64 *)((__int64)src + (__int64)src2);
                                                                                dst3 = 0;
                                                                                if (!__OFSUB(dst3, v_58)) {
                                                                                    if (src2 >= *(__int64 *)((__int64)src + (__int64)a4 - 88)) {
                                                                                        a3 = (struct Struct_3_t *)v_58;
                                                                                        /* cmp result , a3 */;
                                                                                        a4 = (size_t *)result;
                                                                                        a4 += 0;
                                                                                        a2 += 88;
                                                                                        ptr2 -= 88;
                                                                                        a2 = (struct Struct_2_t *)v_48;
                                                                                        src2 = (__int64 *)v_78;
                                                                                        if (a2 < v_68) {
                                                                                            result = a2 + 1;
                                                                                            a4 = 0;
                                                                                            do {
                                                                                                ptr3 = (__int64)(__int64)a2 * 88;
                                                                                                v_48 = (__int64)result;
                                                                                                ptr2 = (__int64)dst + (__int64)ptr3;
                                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)ptr3));
                                                                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)ptr3 + 16));
                                                                                                xmm2 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)ptr3 + 32));
                                                                                                xmm3 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)ptr3 + 48));
                                                                                                _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)ptr3), xmm0);
                                                                                                result = *(__int64 *)((__int64)src2 + (__int64)ptr3 + 80);
                                                                                                *(__int64 *)((__int64)dst + (__int64)ptr3 + 80) = result;
                                                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)src2 + (__int64)ptr3 + 64));
                                                                                                _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)ptr3 + 64), xmm0);
                                                                                                _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)ptr3 + 48), xmm3);
                                                                                                _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)ptr3 + 32), xmm2);
                                                                                                _mm_storeu_si128((__m128i *)((__int64)dst + (__int64)ptr3 + 16), xmm1);
                                                                                                i = *(__int64 *)((__int64)dst + (__int64)ptr3);
                                                                                                result = 80;
                                                                                                a2 = (struct Struct_2_t *)i;
                                                                                                a2 = (struct Struct_2_t *)(-(__int64)a2);
                                                                                                a2 = 80;
                                                                                                a2 = *(__int64 *)((__int64)ptr2 + (__int64)a2);
                                                                                                if (!__OFSUB(a4, *(ptr2 - 88))) {
                                                                                                    dst2 = (__int64)dst + (__int64)ptr3;
                                                                                                    dst2 -= 88;
                                                                                                    if (a2 >= *(__int64 *)((__int64)dst2 + (__int64)result)) {
                                                                                                        a2 = (struct Struct_2_t *)v_48;
                                                                                                        a3 = (struct Struct_3_t *)v_68;
                                                                                                        /* cmp a2 , a3 */;
                                                                                                        result = (__int64 *)a2;
                                                                                                        result += 0;
                                                                                                        result = (__int64)(__int64)v2 * 88;
                                                                                                        a2 = (__int64)a1 + (__int64)result;
                                                                                                        a2 -= 88;
                                                                                                        result = (__int64 *)((__int64)result + (__int64)ptr);
                                                                                                        result -= 88;
                                                                                                        a1 = dst - 88;
                                                                                                        a3 = 0;
                                                                                                        ptr2 = (struct Struct_5_t *)v_58;
                                                                                                        do {
                                                                                                            dst3 = 80;
                                                                                                            src2 = 80;
                                                                                                            if (!__OFSUB(a3, ptr->field_0)) {
                                                                                                                dst2 = *(__int64 *)((__int64)dst + (__int64)src2);
                                                                                                                i = 0;
                                                                                                                src2 = 0;
                                                                                                                src = (dst2 >= *(__int64 *)((__int64)ptr + (__int64)dst3)) ? 1 : 0;
                                                                                                                dst3 = (dst2 < *(__int64 *)((__int64)ptr + (__int64)dst3)) ? 1 : 0;
                                                                                                                dst2 = (__int64 *)ptr;
                                                                                                                if (0 /* unresolved: flags < */) dst2 = dst;
                                                                                                                ptr3 = (struct Struct_6_t *)arg_50;
                                                                                                                a4 = (size_t *)v_38;
                                                                                                                a4[10] = ptr3;
                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)(dst2 + 64));
                                                                                                                _mm_storeu_si128((__m128i *)(a4 + 64), xmm0);
                                                                                                                xmm0 = _mm_loadu_si128((__m128i *)dst2);
                                                                                                                xmm1 = _mm_loadu_si128((__m128i *)(dst2 + 16));
                                                                                                                xmm2 = _mm_loadu_si128((__m128i *)(dst2 + 32));
                                                                                                                xmm3 = _mm_loadu_si128((__m128i *)(dst2 + 48));
                                                                                                                _mm_storeu_si128((__m128i *)(a4 + 48), xmm3);
                                                                                                                _mm_storeu_si128((__m128i *)(a4 + 32), xmm2);
                                                                                                                _mm_storeu_si128((__m128i *)(a4 + 16), xmm1);
                                                                                                                _mm_storeu_si128((__m128i *)a4, xmm0);
                                                                                                                dst2 = 80;
                                                                                                                ptr3 = 80;
                                                                                                                if (!__OFSUB(a3, *result)) {
                                                                                                                    ptr3 = *(__int64 *)((__int64)result + (__int64)ptr3);
                                                                                                                    if (!__OFSUB(a3, a1->field_0)) {
                                                                                                                        src2 = dst3;
                                                                                                                        a4 = (__int64)(__int64)src2 * 88;
                                                                                                                        dst = (__int64 *)((__int64)dst + (__int64)a4);
                                                                                                                        a4 = (__int64)(__int64)i * 88;
                                                                                                                        ptr = (struct Struct_4_t *)((__int64)ptr + (__int64)a4);
                                                                                                                        v_38 += 88;
                                                                                                                        a4 = *(__int64 *)((__int64)a1 + (__int64)dst2);
                                                                                                                        /* cmp ptr3 , a4 */;
                                                                                                                        src2 = 0;
                                                                                                                        src2 -= 1;
                                                                                                                        a4 = (size_t *)result;
                                                                                                                        if (ptr3 < a4) a4 = a1;
                                                                                                                        dst3 = a4[10];
                                                                                                                        ((__int64 *)a2)[10] = (__int64)(dst3);
                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)(a4 + 64));
                                                                                                                        _mm_storeu_si128((__m128i *)(a2 + 64), xmm0);
                                                                                                                        xmm0 = _mm_loadu_si128((__m128i *)a4);
                                                                                                                        xmm1 = _mm_loadu_si128((__m128i *)(a4 + 16));
                                                                                                                        xmm2 = _mm_loadu_si128((__m128i *)(a4 + 32));
                                                                                                                        xmm3 = _mm_loadu_si128((__m128i *)(a4 + 48));
                                                                                                                        _mm_storeu_si128((__m128i *)(a2 + 48), xmm3);
                                                                                                                        _mm_storeu_si128((__m128i *)(a2 + 32), xmm2);
                                                                                                                        _mm_storeu_si128((__m128i *)(a2 + 16), xmm1);
                                                                                                                        _mm_storeu_si128((__m128i *)a2, xmm0);
                                                                                                                        a4 = 0;
                                                                                                                        a4 = 0;
                                                                                                                        src2 = (__int64 *)((__int64)(__int64)(__int64)src2 * 88);
                                                                                                                        result = (__int64 *)((__int64)result + (__int64)src2);
                                                                                                                        a4 = (size_t *)((__int64)(__int64)(__int64)a4 * 88);
                                                                                                                        a1 = (struct Struct_1_t *)((__int64)a1 + (__int64)a4);
                                                                                                                        a2 -= 88;
                                                                                                                        --ptr2;
                                                                                                                        a1 += 88;
                                                                                                                        if (((__int64)v2 & 1) != 0) {
                                                                                                                            a2 = 0;
                                                                                                                            a3 = 0;
                                                                                                                            a2 = (ptr >= a1) ? 1 : 0;
                                                                                                                            a3 = (ptr < a1) ? 1 : 0;
                                                                                                                            a4 = (size_t *)dst;
                                                                                                                            if (ptr < a1) a4 = ptr;
                                                                                                                            src2 = a4[10];
                                                                                                                            dst3 = (__int64 *)v_38;
                                                                                                                            *(dst3 + 80) = src2;
                                                                                                                            xmm0 = _mm_loadu_si128((__m128i *)(a4 + 64));
                                                                                                                            _mm_storeu_si128((__m128i *)(dst3 + 64), xmm0);
                                                                                                                            xmm0 = _mm_loadu_si128((__m128i *)a4);
                                                                                                                            xmm1 = _mm_loadu_si128((__m128i *)(a4 + 16));
                                                                                                                            xmm2 = _mm_loadu_si128((__m128i *)(a4 + 32));
                                                                                                                            xmm3 = _mm_loadu_si128((__m128i *)(a4 + 48));
                                                                                                                            _mm_storeu_si128((__m128i *)(dst3 + 48), xmm3);
                                                                                                                            _mm_storeu_si128((__m128i *)(dst3 + 32), xmm2);
                                                                                                                            _mm_storeu_si128((__m128i *)(dst3 + 16), xmm1);
                                                                                                                            _mm_storeu_si128((__m128i *)dst3, xmm0);
                                                                                                                            a3 = (struct Struct_3_t *)((__int64)(__int64)(__int64)a3 * 88);
                                                                                                                            ptr = (struct Struct_4_t *)((__int64)ptr + (__int64)a3);
                                                                                                                            a2 = (struct Struct_2_t *)((__int64)(__int64)(__int64)a2 * 88);
                                                                                                                            dst = (__int64 *)((__int64)dst + (__int64)a2);
                                                                                                                        }
                                                                                                                        if (ptr != a1) JUMPOUT(0x140072cd2);
                                                                                                                        result += 88;
                                                                                                                        if (dst != result) JUMPOUT(0x140072cd2);
                                                                                                                        return (__int64)result;
                                                                                                                    }
                                                                                                                    a4 = a1->field_8;
                                                                                                                    dst2 = a4 - 3;
                                                                                                                    a4 = 2;
                                                                                                                    if (a4 < 3) dst2 = a4;
                                                                                                                    a4 = &off_14011E9F0;
                                                                                                                    dst2 = a4[(__int64)dst2];
                                                                                                                    return (__int64)dst2;
                                                                                                                }
                                                                                                                ptr3 = (struct Struct_6_t *)arg_8;
                                                                                                                a4 = ptr3 - 3;
                                                                                                                ptr3 = 2;
                                                                                                                if (ptr3 < 3) a4 = ptr3;
                                                                                                                ptr3 = &off_14011E9D8;
                                                                                                                ptr3 = ((__int64 *)ptr3)[(__int64)a4];
                                                                                                                return (__int64)ptr3;
                                                                                                            }
                                                                                                            dst3 = ptr->field_8;
                                                                                                            dst2 = dst3 - 3;
                                                                                                            a4 = 2;
                                                                                                            if (dst3 < 3) dst2 = a4;
                                                                                                            a4 = &off_14011E9C0;
                                                                                                            dst3 = a4[(__int64)dst2];
                                                                                                            return (__int64)dst3;
                                                                                                        } while (!((ptr2 == 0)));
                                                                                                        return (__int64)dst3;
                                                                                                    }
                                                                                                    ptr3 = (struct Struct_6_t *)((__int64)ptr3 + (__int64)src2);
                                                                                                    result = ptr2->field_8;
                                                                                                    a2 = ptr2->field_C;
                                                                                                    src2 = result - 3;
                                                                                                    v_40 = (__int64)result;
                                                                                                    result = 2;
                                                                                                    if (result < 3) src2 = result;
                                                                                                    result = (__int64 *)i;
                                                                                                    result = (__int64 *)(-(__int64)result);
                                                                                                    a1 = ptr2->field_10;
                                                                                                    result = ptr2->field_18;
                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)(ptr3 + 28));
                                                                                                    xmm1 = _mm_loadu_si128((__m128i *)(ptr3 + 40));
                                                                                                    _mm_storeu_si128((__m128i *)&v_bc, xmm1);
                                                                                                    _mm_store_si128((__m128i *)&v_b0, xmm0);
                                                                                                    dst3 = ptr2->field_38;
                                                                                                    a3 = ptr3->field_4C;
                                                                                                    v_90 = (__int64)a3;
                                                                                                    xmm0 = _mm_loadu_si128((__m128i *)(ptr3 + 60));
                                                                                                    _mm_store_si128((__m128i *)&v_80, xmm0);
                                                                                                    xmm0 = _mm_loadl_epi64((__m128i *)&ptr2->field_50);
                                                                                                    v_50 = (__int64)a1;
                                                                                                    if ((0 /* overflow check on (-result) */)) {
                                                                                                        a3 = (struct Struct_3_t *)arg_50;
                                                                                                        ptr2->field_50 = a3;
                                                                                                        xmm1 = _mm_loadu_si128((__m128i *)(dst2 + 64));
                                                                                                        _mm_storeu_si128((__m128i *)(ptr2 + 64), xmm1);
                                                                                                        xmm1 = _mm_loadu_si128((__m128i *)dst2);
                                                                                                        xmm2 = _mm_loadu_si128((__m128i *)(dst2 + 16));
                                                                                                        xmm3 = _mm_loadu_si128((__m128i *)(dst2 + 32));
                                                                                                        xmm4 = _mm_loadu_si128((__m128i *)(dst2 + 48));
                                                                                                        _mm_storeu_si128((__m128i *)(ptr2 + 48), xmm4);
                                                                                                        _mm_storeu_si128((__m128i *)(ptr2 + 32), xmm3);
                                                                                                        _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm2);
                                                                                                        _mm_storeu_si128((__m128i *)ptr2, xmm1);
                                                                                                        while (dst2 != dst) {
                                                                                                            ptr3 = (struct Struct_6_t *)dst2;
                                                                                                            src = (__int64 *)a2;
                                                                                                            if (src2 == 0) {
                                                                                                                dst2 = ptr3 - 88;
                                                                                                                a3 = 80;
                                                                                                                if (!__OFSUB(a4, *dst2)) {
                                                                                                                    ptr2 = (struct Struct_5_t *)ptr3;
                                                                                                                    *(__int64 *)ptr3 = (__int64)(i);
                                                                                                                    a1 = (struct Struct_1_t *)v_40;
                                                                                                                    ptr3->field_8 = a1;
                                                                                                                    ptr3->field_C = a2;
                                                                                                                    a1 = (struct Struct_1_t *)v_50;
                                                                                                                    ptr3->field_10 = a1;
                                                                                                                    ptr3->field_18 = result;
                                                                                                                    xmm1 = _mm_load_si128((__m128i *)&v_b0);
                                                                                                                    _mm_storeu_si128((__m128i *)(ptr3 + 28), xmm1);
                                                                                                                    xmm1 = _mm_loadu_si128((__m128i *)&v_bc);
                                                                                                                    _mm_storeu_si128((__m128i *)(ptr3 + 40), xmm1);
                                                                                                                    ptr3->field_38 = dst3;
                                                                                                                    xmm1 = _mm_load_si128((__m128i *)&v_80);
                                                                                                                    _mm_storeu_si128((__m128i *)(ptr3 + 60), xmm1);
                                                                                                                    result = (__int64 *)v_90;
                                                                                                                    ptr3->field_4C = result;
                                                                                                                    /* movlps %xmm0, 80(%(__int64)ptr3) */;
                                                                                                                    a1 = (struct Struct_1_t *)v_38;
                                                                                                                    src2 = (__int64 *)v_78;
                                                                                                                    return (__int64)src2;
                                                                                                                }
                                                                                                                a1 = *(__int64 *)(ptr3 - 80);
                                                                                                                a3 = a1 - 3;
                                                                                                                a1 = 2;
                                                                                                                if (a1 < 3) a3 = a1;
                                                                                                                a1 = &off_14011E990;
                                                                                                                a3 = ((__int64 *)a1)[(__int64)a3];
                                                                                                                return (__int64)a3;
                                                                                                            }
                                                                                                            src = dst3;
                                                                                                            if (src2 != 1) {
                                                                                                                return (__int64)src;
                                                                                                            }
                                                                                                            src = result;
                                                                                                            return (__int64)src;
                                                                                                        }
                                                                                                        ptr3 = (struct Struct_6_t *)dst;
                                                                                                        return (__int64)ptr3;
                                                                                                    }
                                                                                                    src2 = ptr2->field_50;
                                                                                                    a3 = (struct Struct_3_t *)arg_50;
                                                                                                    ptr2->field_50 = a3;
                                                                                                    xmm1 = _mm_loadu_si128((__m128i *)(dst2 + 64));
                                                                                                    _mm_storeu_si128((__m128i *)(ptr2 + 64), xmm1);
                                                                                                    xmm1 = _mm_loadu_si128((__m128i *)dst2);
                                                                                                    xmm2 = _mm_loadu_si128((__m128i *)(dst2 + 16));
                                                                                                    xmm3 = _mm_loadu_si128((__m128i *)(dst2 + 32));
                                                                                                    xmm4 = _mm_loadu_si128((__m128i *)(dst2 + 48));
                                                                                                    _mm_storeu_si128((__m128i *)(ptr2 + 48), xmm4);
                                                                                                    _mm_storeu_si128((__m128i *)(ptr2 + 32), xmm3);
                                                                                                    _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm2);
                                                                                                    _mm_storeu_si128((__m128i *)ptr2, xmm1);
                                                                                                    while (dst2 != dst) {
                                                                                                        ptr3 = (struct Struct_6_t *)dst2;
                                                                                                        src = 80;
                                                                                                        if (!__OFSUB(a4, v_58)) {
                                                                                                            dst2 = ptr3 - 88;
                                                                                                            ptr2 = (struct Struct_5_t *)ptr3;
                                                                                                            return (__int64)ptr2;
                                                                                                        }
                                                                                                        a1 = *(__int64 *)(ptr3 - 80);
                                                                                                        a3 = a1 - 3;
                                                                                                        a1 = 2;
                                                                                                        if (a1 < 3) a3 = a1;
                                                                                                        a1 = &off_14011E978;
                                                                                                        src = ((__int64 *)a1)[(__int64)a3];
                                                                                                        return (__int64)src;
                                                                                                    }
                                                                                                    return (__int64)src;
                                                                                                }
                                                                                                result = *(__int64 *)(ptr2 - 80);
                                                                                                a3 = result - 3;
                                                                                                result = 2;
                                                                                                if (result < 3) a3 = result;
                                                                                                result = &off_14011E960;
                                                                                                result = v_0[(__int64)a3];
                                                                                                dst2 = (__int64)dst + (__int64)ptr3;
                                                                                                dst2 -= 88;
                                                                                                if (a2 >= *(__int64 *)((__int64)dst2 + (__int64)result)) {
                                                                                                    return (__int64)dst2;
                                                                                                }
                                                                                                return (__int64)dst2;
                                                                                            } while (a2 < a3);
                                                                                        }
                                                                                        return (__int64)dst2;
                                                                                    }
                                                                                    a3 = (struct Struct_3_t *)((__int64)a3 + (__int64)a1);
                                                                                    i = (struct Struct_7_t *)arg_8;
                                                                                    ptr3 = (struct Struct_6_t *)arg_c;
                                                                                    src2 = i - 3;
                                                                                    a1 = 2;
                                                                                    if (i < 3) src2 = a1;
                                                                                    v_50 = (__int64)dst2;
                                                                                    a4 = (size_t *)dst2;
                                                                                    a4 = (size_t *)(-(__int64)a4);
                                                                                    a4 = (size_t *)arg_10;
                                                                                    v_60 = (__int64)a4;
                                                                                    a4 = (size_t *)arg_18;
                                                                                    v_40 = (__int64)a4;
                                                                                    xmm0 = _mm_loadu_si128((__m128i *)(a3 + 28));
                                                                                    xmm1 = _mm_loadu_si128((__m128i *)(a3 + 40));
                                                                                    _mm_storeu_si128((__m128i *)&v_bc, xmm1);
                                                                                    _mm_store_si128((__m128i *)&v_b0, xmm0);
                                                                                    a4 = (size_t *)arg_38;
                                                                                    dst3 = ((__int64 *)a3)[9];
                                                                                    v_90 = (__int64)dst3;
                                                                                    xmm0 = _mm_loadu_si128((__m128i *)(a3 + 60));
                                                                                    _mm_store_si128((__m128i *)&v_80, xmm0);
                                                                                    xmm0 = _mm_cvtsi64_si128((__int64)(arg_50));
                                                                                    v_70 = (__int64)i;
                                                                                    if ((0 /* unresolved: flags !OF */)) {
                                                                                        src2 = (__int64 *)arg_50;
                                                                                        a3 = (struct Struct_3_t *)ptr2;
                                                                                        src = (__int64 *)a2;
                                                                                        dst3 = (__int64 *)v_8;
                                                                                        arg_50 = (__int64)dst3;
                                                                                        xmm1 = _mm_loadu_si128((__m128i *)&v_18);
                                                                                        _mm_storeu_si128((__m128i *)&arg_40, xmm1);
                                                                                        xmm1 = _mm_loadu_si128((__m128i *)&v_58);
                                                                                        xmm2 = _mm_loadu_si128((__m128i *)&v_48);
                                                                                        xmm3 = _mm_loadu_si128((__m128i *)&v_38);
                                                                                        xmm4 = _mm_loadu_si128((__m128i *)&v_28);
                                                                                        _mm_storeu_si128((__m128i *)&arg_30, xmm4);
                                                                                        _mm_storeu_si128((__m128i *)&arg_20, xmm3);
                                                                                        _mm_storeu_si128((__m128i *)&arg_10, xmm2);
                                                                                        _mm_storeu_si128((__m128i *)&*src, xmm1);
                                                                                        while (a3 != 0) {
                                                                                            dst3 = 80;
                                                                                            dst2 = 0;
                                                                                            if (!__OFSUB(dst2, v_b0)) {
                                                                                                dst2 = src - 88;
                                                                                                a3 += 88;
                                                                                                /* cmp src2 , *(__int64 *)((__int64)dst3 + (__int64)src - 176) */;
                                                                                                src = dst2;
                                                                                                i = 2;
                                                                                                a1 = (struct Struct_1_t *)v_50;
                                                                                                *dst2 = a1;
                                                                                                a1 = (struct Struct_1_t *)v_70;
                                                                                                arg_8 = (int)a1;
                                                                                                arg_c = (__int64)ptr3;
                                                                                                a1 = (struct Struct_1_t *)v_60;
                                                                                                arg_10 = (int)a1;
                                                                                                a1 = (struct Struct_1_t *)v_40;
                                                                                                arg_18 = (int)a1;
                                                                                                xmm1 = _mm_load_si128((__m128i *)&v_b0);
                                                                                                _mm_storeu_si128((__m128i *)(dst2 + 28), xmm1);
                                                                                                xmm1 = _mm_loadu_si128((__m128i *)&v_bc);
                                                                                                _mm_storeu_si128((__m128i *)(dst2 + 40), xmm1);
                                                                                                arg_38 = (int)a4;
                                                                                                xmm1 = _mm_load_si128((__m128i *)&v_80);
                                                                                                _mm_storeu_si128((__m128i *)(dst2 + 60), xmm1);
                                                                                                a3 = (struct Struct_3_t *)v_90;
                                                                                                arg_4c = (int)a3;
                                                                                                /* movlps %xmm0, 80(%(__int64)dst2) */;
                                                                                                a1 = (struct Struct_1_t *)v_38;
                                                                                                return (__int64)a1;
                                                                                            }
                                                                                            dst3 = (__int64 *)v_a8;
                                                                                            dst2 = dst3 - 3;
                                                                                            if (dst3 < 3) dst2 = a1;
                                                                                            dst3 = &off_14011EA50;
                                                                                            dst3 = dst3[(__int64)dst2];
                                                                                            return (__int64)dst3;
                                                                                        }
                                                                                        dst2 = (__int64 *)ptr;
                                                                                        return (__int64)dst2;
                                                                                    }
                                                                                    a3 = 0;
                                                                                    src = (__int64 *)a2;
                                                                                    dst3 = (__int64 *)v_8;
                                                                                    arg_50 = (__int64)dst3;
                                                                                    xmm1 = _mm_loadu_si128((__m128i *)&v_18);
                                                                                    _mm_storeu_si128((__m128i *)&arg_40, xmm1);
                                                                                    xmm1 = _mm_loadu_si128((__m128i *)&v_58);
                                                                                    xmm2 = _mm_loadu_si128((__m128i *)&v_48);
                                                                                    xmm3 = _mm_loadu_si128((__m128i *)&v_38);
                                                                                    xmm4 = _mm_loadu_si128((__m128i *)&v_28);
                                                                                    _mm_storeu_si128((__m128i *)&arg_30, xmm4);
                                                                                    _mm_storeu_si128((__m128i *)&arg_20, xmm3);
                                                                                    _mm_storeu_si128((__m128i *)&arg_10, xmm2);
                                                                                    _mm_storeu_si128((__m128i *)&*src, xmm1);
                                                                                    while (ptr2 != a3) {
                                                                                        i = (struct Struct_7_t *)ptr3;
                                                                                        if (src2 == 0) {
                                                                                            dst3 = 80;
                                                                                            dst2 = 0;
                                                                                            if (!__OFSUB(dst2, v_b0)) {
                                                                                                dst2 = src - 88;
                                                                                                a3 -= 88;
                                                                                                /* cmp i , *(__int64 *)((__int64)dst3 + (__int64)src - 176) */;
                                                                                                src = dst2;
                                                                                                return (__int64)src;
                                                                                            }
                                                                                            dst3 = (__int64 *)v_a8;
                                                                                            dst2 = dst3 - 3;
                                                                                            if (dst3 < 3) dst2 = a1;
                                                                                            dst3 = &off_14011EA38;
                                                                                            dst3 = dst3[(__int64)dst2];
                                                                                            return (__int64)dst3;
                                                                                        }
                                                                                        i = (struct Struct_7_t *)a4;
                                                                                        if (src2 != 1) {
                                                                                            return (__int64)i;
                                                                                        }
                                                                                        i = (struct Struct_7_t *)v_40;
                                                                                        return (__int64)i;
                                                                                    }
                                                                                    return (__int64)i;
                                                                                }
                                                                                a4 = (size_t *)v_50;
                                                                                dst3 = a4 - 3;
                                                                                if (a4 < 3) dst3 = i;
                                                                                a1 = &off_14011EA20;
                                                                                a4 = ((__int64 *)a1)[(__int64)dst3];
                                                                                a1 = (struct Struct_1_t *)v_38;
                                                                                if (src2 >= *(__int64 *)((__int64)src + (__int64)a4 - 88)) {
                                                                                    return (__int64)a1;
                                                                                }
                                                                                return (__int64)a1;
                                                                            } while (result < a3);
                                                                        }
                                                                        return (__int64)a1;
                                                                    }
                                                                    return (__int64)a1;
                                                                }
                                                                result = (__int64)(__int64)a2 * 88;
                                                                a2 = (struct Struct_2_t *)(~(__int64)a2);
                                                                a3 = (__int64)(__int64)a2 * 88;
                                                                a2 = *(__int64 *)((__int64)dst3 + (__int64)a3 + 80);
                                                                *(__int64 *)((__int64)a1 + (__int64)result + 80) = a2;
                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3 + 64));
                                                                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)result + 64), xmm0);
                                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3));
                                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3 + 16));
                                                                xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3 + 32));
                                                                xmm3 = _mm_loadu_si128((__m128i *)((__int64)dst3 + (__int64)a3 + 48));
                                                                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)result + 48), xmm3);
                                                                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)result + 32), xmm2);
                                                                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)result + 16), xmm1);
                                                                _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)result), xmm0);
                                                                return _mm_cvtsi128_si64(xmm3);
                                                            }
                                                            a2 = 0;
                                                            ptr3 = (struct Struct_6_t *)v_58;
                                                            dst3 = (__int64 *)v_38;
                                                            return (__int64)dst3;
                                                        }
                                                        return (__int64)dst3;
                                                    }
                                                    dst3 -= 88;
                                                    a2 = (__int64)(__int64)i * 88;
                                                    a3 = (struct Struct_3_t *)arg_50;
                                                    *(__int64 *)((__int64)ptr + (__int64)a2 + 80) = a3;
                                                    xmm0 = _mm_loadu_si128((__m128i *)(result + 64));
                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 64), xmm0);
                                                    xmm0 = _mm_loadu_si128((__m128i *)result);
                                                    xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
                                                    xmm2 = _mm_loadu_si128((__m128i *)(result + 32));
                                                    xmm3 = _mm_loadu_si128((__m128i *)(result + 48));
                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 48), xmm3);
                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 32), xmm2);
                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 16), xmm1);
                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2), xmm0);
                                                    ++i;
                                                    result += 88;
                                                } while (true);
                                            }
                                            if (src2 < v2) JUMPOUT(0x140072c8c);
                                            a3 = (struct Struct_3_t *)v_48;
                                            a3 = (struct Struct_3_t *)((__int64)a3 + (__int64)a1);
                                            result = rsp + 176;
                                            v_28 = (__int64)result;
                                            ptr3 = (struct Struct_6_t *)v_58;
                                            v_20 = (__int64)ptr3;
                                            sub_1400719A0(a3, a2, ptr, ptr2);
                                            a1 = (struct Struct_1_t *)v_38;
                                            result = v2;
                                            return (__int64)result;
                                        }
                                        result = (__int64 *)v_48;
                                        result = (__int64 *)((__int64)result + (__int64)a1);
                                        a3 = v2 + 1;
                                        if (src2 != a3) {
                                            dst3 = (__int64 *)a2;
                                            dst3 = (__int64 *)((__int64)(__int64)dst3 & -2);
                                            ptr2 += v_60;
                                            a3 = (struct Struct_3_t *)result;
                                            src2 = 0;
                                            i = 0x1FFFFFFFFFFFFFFE;
                                            do {
                                                a4 = ptr2->field_50;
                                                ((__int64 *)a3)[10] = (__int64)(a4);
                                                xmm0 = _mm_loadu_si128((__m128i *)(ptr2 + 64));
                                                _mm_storeu_si128((__m128i *)(a3 + 64), xmm0);
                                                xmm0 = _mm_loadu_si128((__m128i *)ptr2);
                                                xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + 16));
                                                xmm2 = _mm_loadu_si128((__m128i *)(ptr2 + 32));
                                                xmm3 = _mm_loadu_si128((__m128i *)(ptr2 + 48));
                                                _mm_storeu_si128((__m128i *)(a3 + 48), xmm3);
                                                _mm_storeu_si128((__m128i *)(a3 + 32), xmm2);
                                                _mm_storeu_si128((__m128i *)(a3 + 16), xmm1);
                                                _mm_storeu_si128((__m128i *)a3, xmm0);
                                                a4 = src2 + 2;
                                                src2 = (__int64 *)((__int64)(__int64)src2 ^ (__int64)i);
                                                src2 = (__int64 *)((__int64)(__int64)(__int64)src2 * 88);
                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)src2));
                                                xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)src2 + 16));
                                                xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)src2 + 32));
                                                xmm3 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)src2 + 48));
                                                _mm_storeu_si128((__m128i *)(a3 + 88), xmm0);
                                                _mm_storeu_si128((__m128i *)(a3 + 104), xmm1);
                                                _mm_storeu_si128((__m128i *)(a3 + 120), xmm2);
                                                _mm_storeu_si128((__m128i *)(a3 + 136), xmm3);
                                                xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)src2 + 64));
                                                _mm_storeu_si128((__m128i *)(a3 + 152), xmm0);
                                                src2 = *(__int64 *)((__int64)dst2 + (__int64)src2 + 80);
                                                ((__int64 *)a3)[21] = (__int64)(src2);
                                                a3 += 176;
                                                ptr2 -= 176;
                                                src2 = (__int64 *)a4;
                                            } while (dst3 != a4);
                                            src2 = (__int64 *)v_40;
                                            if (((__int64)a2 & 1) == 0) {
                                                return (__int64)src2;
                                            }
                                            src2 = (__int64)(__int64)a4 * 88;
                                            a4 = (size_t *)(~(__int64)a4);
                                            a3 = (__int64)(__int64)a4 * 88;
                                            a4 = *(__int64 *)((__int64)dst2 + (__int64)a3 + 80);
                                            *(__int64 *)((__int64)result + (__int64)src2 + 80) = a4;
                                            xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)a3 + 64));
                                            _mm_storeu_si128((__m128i *)((__int64)result + (__int64)src2 + 64), xmm0);
                                            xmm0 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)a3));
                                            xmm1 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)a3 + 16));
                                            xmm2 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)a3 + 32));
                                            xmm3 = _mm_loadu_si128((__m128i *)((__int64)dst2 + (__int64)a3 + 48));
                                            _mm_storeu_si128((__m128i *)((__int64)result + (__int64)src2 + 48), xmm3);
                                            _mm_storeu_si128((__m128i *)((__int64)result + (__int64)src2 + 32), xmm2);
                                            _mm_storeu_si128((__m128i *)((__int64)result + (__int64)src2 + 16), xmm1);
                                            _mm_storeu_si128((__m128i *)((__int64)result + (__int64)src2), xmm0);
                                            src2 = (__int64 *)v_40;
                                            return (__int64)src2;
                                        }
                                        a4 = 0;
                                        return (__int64)a4;
                                    }
                                    a2 = (__int64)(__int64)v2 * 88;
                                    a3 = (struct Struct_3_t *)arg_50;
                                    *(__int64 *)((__int64)i + (__int64)a2 - 8) = a3;
                                    xmm0 = _mm_loadu_si128((__m128i *)(result + 64));
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)a2 - 24), xmm0);
                                    xmm0 = _mm_loadu_si128((__m128i *)result);
                                    xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
                                    xmm2 = _mm_loadu_si128((__m128i *)(result + 32));
                                    xmm3 = _mm_loadu_si128((__m128i *)(result + 48));
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)a2 - 40), xmm3);
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)a2 - 56), xmm2);
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)a2 - 72), xmm1);
                                    _mm_storeu_si128((__m128i *)((__int64)i + (__int64)a2 - 88), xmm0);
                                    i -= 88;
                                    result += 88;
                                    a2 = (struct Struct_2_t *)a4;
                                    a1 = (struct Struct_1_t *)v_38;
                                }
                                a4 = ptr3->field_8;
                                dst3 = a4 - 3;
                                if (a4 < 3) dst3 = dst;
                                a4 = &off_14011EB40;
                                a4 = a4[(__int64)dst3];
                                return (__int64)a4;
                            } while (result < a3);
                            return (__int64)a4;
                        } while (true);
                    }
                    result = 80;
                    a3 = 80;
                    if (!__OFSUB(src, i->field_0)) {
                        if (!__OFSUB(src, ptr3->field_0)) {
                            a2 = *(__int64 *)((__int64)i + (__int64)a3);
                            if (a2 < *(__int64 *)((__int64)ptr3 + (__int64)result)) {
                                return (__int64)a2;
                            }
                            return (__int64)a2;
                        }
                        result = ptr3->field_8;
                        a2 = result - 3;
                        if (result < 3) a2 = dst;
                        result = &off_14011EB10;
                        result = v_0[(__int64)a2];
                        a2 = *(__int64 *)((__int64)i + (__int64)a3);
                        if (a2 >= *(__int64 *)((__int64)ptr3 + (__int64)result)) {
                            return (__int64)a2;
                        }
                        return (__int64)a2;
                    }
                    a3 = i->field_8;
                    a2 = a3 - 3;
                    if (a3 < 3) a2 = dst;
                    a3 = &off_14011EAF8;
                    a3 = ((__int64 *)a3)[(__int64)a2];
                    if (__OFSUB(src, ptr3->field_0)) {
                        return (__int64)a3;
                    }
                    return (__int64)a3;
                }
                src2 = a1->field_0;
                dst2 = 80;
                result = src2;
                result = (__int64 *)(-(__int64)result);
                a4 = 80;
                if ((0 /* overflow check on (-result) */)) {
                    result = a2->field_0;
                    dst3 = result;
                    dst3 = (__int64 *)(-(__int64)dst3);
                    if ((0 /* overflow check on (-dst3) */)) {
                        src2 = (__int64 *)(-(__int64)src2);
                        dst3 = 80;
                        ptr2 = 80;
                        if ((0 /* overflow check on (-src2) */)) {
                            src2 = a3->field_0;
                            v2 = src2;
                            v2 = (__int64 *)(-(__int64)v2);
                            if ((0 /* overflow check on (-v2) */)) {
                                a1 = (struct Struct_1_t *)v_38;
                                a4 = *(__int64 *)((__int64)a1 + (__int64)a4);
                                dst2 = *(__int64 *)((__int64)a2 + (__int64)dst2);
                                ptr2 = *(__int64 *)((__int64)a1 + (__int64)ptr2);
                                v2 = (a4 < dst2) ? 1 : 0;
                                dst3 = (ptr2 < *(__int64 *)((__int64)a3 + (__int64)dst3)) ? 1 : 0;
                                dst3 = (__int64 *)((__int64)(__int64)dst3 ^ (__int64)v2);
                                ptr3 = (struct Struct_6_t *)a1;
                                ptr2 = (struct Struct_5_t *)v_50;
                                if ((dst3 != 0)) {
                                    return (__int64)ptr2;
                                }
                                result = (__int64 *)(-(__int64)result);
                                result = 80;
                                dst3 = 80;
                                if ((0 /* overflow check on (-result) */)) {
                                    src2 = (__int64 *)(-(__int64)src2);
                                    if ((0 /* overflow check on (-src2) */)) {
                                        src2 = *(__int64 *)((__int64)a2 + (__int64)dst3);
                                        a1 = (a4 < dst2) ? 1 : 0;
                                        result = (src2 < *(__int64 *)((__int64)a3 + (__int64)result)) ? 1 : 0;
                                        result = (__int64 *)((__int64)(__int64)result ^ (__int64)a1);
                                        if (result != 0) a2 = a3;
                                        ptr3 = (struct Struct_6_t *)a2;
                                        a1 = (struct Struct_1_t *)v_38;
                                        return (__int64)a1;
                                    }
                                    result = a3->field_8;
                                    src2 = result - 3;
                                    if (result < 3) src2 = dst;
                                    result = &off_14011EAE0;
                                    result = v_0[(__int64)src2];
                                    return (__int64)result;
                                }
                                dst3 = a2->field_8;
                                ptr2 = dst3 - 3;
                                if (dst3 < 3) ptr2 = dst;
                                a1 = &off_14011EAC8;
                                dst3 = ((__int64 *)a1)[(__int64)ptr2];
                                ptr2 = (struct Struct_5_t *)v_50;
                                return (__int64)ptr2;
                            }
                            dst3 = a3->field_8;
                            v2 = dst3 - 3;
                            if (dst3 < 3) v2 = dst;
                            a1 = &off_14011EAB0;
                            dst3 = ((__int64 *)a1)[(__int64)v2];
                            return (__int64)dst3;
                        }
                        a1 = (struct Struct_1_t *)v_38;
                        src2 = a1->field_8;
                        ptr2 = src2 - 3;
                        if (src2 < 3) ptr2 = dst;
                        a1 = &off_14011EA98;
                        ptr2 = ((__int64 *)a1)[(__int64)ptr2];
                        src2 = a3->field_0;
                        v2 = src2;
                        v2 = (__int64 *)(-(__int64)v2);
                        if ((0 /* overflow check on (-v2) */)) {
                            return (__int64)v2;
                        }
                        return (__int64)v2;
                    }
                    a1 = a2->field_8;
                    dst3 = a1 - 3;
                    if (a1 < 3) dst3 = dst;
                    a1 = &off_14011EA80;
                    dst2 = ((__int64 *)a1)[(__int64)dst3];
                    src2 = (__int64 *)(-(__int64)src2);
                    dst3 = 80;
                    ptr2 = 80;
                    if ((0 /* overflow check on (-src2) */)) {
                        return (__int64)ptr2;
                    }
                    return (__int64)ptr2;
                }
                result = a1->field_8;
                a4 = result - 3;
                if (result < 3) a4 = dst;
                result = &off_14011EA68;
                a4 = v_0[(__int64)a4];
                result = a2->field_0;
                dst3 = result;
                dst3 = (__int64 *)(-(__int64)dst3);
                if ((0 /* overflow check on (-dst3) */)) {
                    return (__int64)dst3;
                }
                return (__int64)dst3;
            }
            v_20 = 1;
            sub_140071090(dst2, result, ptr, ptr2);
            return v_20;
        } while (v2 >= 33);
        return v_20;
    }
    return (__int64)result;
}