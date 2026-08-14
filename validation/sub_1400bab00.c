// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    char _pad_20[32];
    __int64 field_48; // offset 72
    char _pad_48[32];
    __int64 field_70; // offset 112
    char _pad_70[32];
    __int64 field_98; // offset 152
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    char _pad_20[32];
    __int64 field_48; // offset 72
    char _pad_48[32];
    __int64 field_70; // offset 112
    char _pad_70[32];
    __int64 field_98; // offset 152
};

// inferred from 2 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    char _pad_20[32];
    __int64 field_48; // offset 72
};

__int64 sub_1400BCB00();
__int64 sub_1400F27F0();
__int64 sub_1400BA460();

__int64 __fastcall sub_1400BAB00(size_t *a1, size_t *a2, size_t *a3) {
    __int64 rsp;
    int arg_20;
    int v_110;
    int v_118;
    int v_28;
    int v_30;
    __int64 v_38;
    int v_40;
    __int64 v_48;
    int v_80;
    int v_90;
    int v_a0;
    __int64 *v_20;
    struct Struct_1_t *ptr;
    __int64 v2;
    struct Struct_2_t *ptr2;
    __int64 v12;
    __int64 result;
    __int64 *src;
    __int64 *src2;
    struct Struct_3_t *ptr3;
    __m128i xmm0;
    __m128i xmm1;
    __int64 *i;
    __int64 *src3;
    __int64 *src4;
    __int64 v7;

    ptr = (struct Struct_1_t *)a3;
    v2 = (__int64)a2;
    ptr2 = (struct Struct_2_t *)a1;
    if (a2 >= 33) {
        v12 = (__int64)ptr3;
        result = v_118;
        v_30 = result;
        src = (__int64 *)v_110;
        result = ptr - 40;
        v_40 = result;
        v_48 = (__int64)ptr3;
        do {
            src2 = (__int64 *)v2;
            --src;
            while (!((src < 0))) {
                ptr3 = (struct Struct_3_t *)src2;
                ptr3 = (struct Struct_3_t *)((__int64)(__int64)ptr3 >> 3);
                result = ptr3 + (__int64)(__int64)ptr3*4;
                result <<= 5;
                result += (__int64)ptr2;
                a3 = (__int64)(__int64)ptr3 * 280;
                a3 = (size_t *)((__int64)a3 + (__int64)ptr2);
                v_38 = (__int64)src;
                if (src2 >= 64) {
                    sub_1400BCB00(ptr2, result, a3, ptr3);
                    src = (__int64 *)result;
                    src = (__int64 *)((__int64)src - (__int64)ptr2);
                    src = (__int64 *)((__int64)(__int64)src >> 3);
                    a1 = 0xCCCCCCCCCCCCCCCD;
                    src = (__int64 *)((__int64)(__int64)(__int64)src * (__int64)a1);
                    a1 = (size_t *)arg_20;
                    v_a0 = (int)a1;
                    xmm0 = _mm_loadu_si128((__m128i *)result);
                    xmm1 = _mm_loadu_si128((__m128i *)(result + 16));
                    _mm_store_si128((__m128i *)&v_90, xmm1);
                    _mm_store_si128((__m128i *)&v_80, xmm0);
                    if (v_30 == 0) {
                        if (v12 < src2) JUMPOUT(0x1400bb588);
                        i = src2 + (__int64)(__int64)src2*4;
                        src3 = ptr + (__int64)(__int64)i*8;
                        result = src + (__int64)(__int64)src*4;
                        result = ptr2 + result*8;
                        result += 32;
                        v2 = 0;
                        a1 = (size_t *)ptr2;
                        a2 = (size_t *)src3;
                        a3 = (size_t *)src;
                        do {
                            ptr3 = a3 + (__int64)(__int64)a3*4;
                            ptr3 = ptr2 + (__int64)(__int64)ptr3*8;
                            if (a3 == src2) {
                                result =  + v2*8;
                                a3 = result + result*4;
                                sub_1400F27F0(ptr2, ptr, a3, ptr3);
                                a2 = (size_t *)src2;
                                a2 -= v2;
                                v12 = v_48;
                                if ((a2 == 0)) {
                                    if (v2 == 0) {
                                        if (v12 < src2) JUMPOUT(0x1400bb588);
                                        result = src2 + (__int64)(__int64)src2*4;
                                        v_30 = result;
                                        src3 = ptr + result*8;
                                        result = src + (__int64)(__int64)src*4;
                                        result = ptr2 + result*8;
                                        result += 32;
                                        i = 0;
                                        a1 = (size_t *)ptr2;
                                        a2 = (size_t *)src3;
                                        do {
                                            a3 = src + (__int64)(__int64)src*4;
                                            a3 = ptr2 + (__int64)(__int64)a3*8;
                                            if (src == src2) {
                                                result =  + (__int64)(__int64)i*8;
                                                a3 = result + result*4;
                                                sub_1400F27F0(ptr2, ptr, a3, ptr3);
                                                v2 = (__int64)src2;
                                                v2 -= (__int64)i;
                                                if (!((v2 == 0))) {
                                                    result = i + (__int64)(__int64)i*4;
                                                    ptr2 += result*8;
                                                    result = i + 1;
                                                    if (src2 != result) {
                                                        result = v2;
                                                        result &= -2;
                                                        a1 = (size_t *)v_40;
                                                        a2 = (size_t *)v_30;
                                                        a1 += (__int64)(__int64)a2*8;
                                                        a2 = (size_t *)ptr2;
                                                        ptr3 = 0;
                                                        src = (__int64 *)v_38;
                                                        src4 = 0x1FFFFFFFFFFFFFFE;
                                                        do {
                                                            a3 = a1[4];
                                                            a2[4] = a3;
                                                            xmm0 = _mm_loadu_si128((__m128i *)a1);
                                                            xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
                                                            _mm_storeu_si128((__m128i *)(a2 + 16), xmm1);
                                                            _mm_storeu_si128((__m128i *)a2, xmm0);
                                                            a3 = ptr3 + 2;
                                                            ptr3 = (struct Struct_3_t *)((__int64)(__int64)ptr3 ^ (__int64)src4);
                                                            ptr3 += (__int64)(__int64)ptr3*4;
                                                            xmm0 = _mm_loadu_si128((__m128i *)(src3 + (__int64)(__int64)ptr3*8));
                                                            xmm1 = _mm_loadu_si128((__m128i *)(src3 + (__int64)(__int64)ptr3*8 + 16));
                                                            _mm_storeu_si128((__m128i *)(a2 + 40), xmm0);
                                                            _mm_storeu_si128((__m128i *)(a2 + 56), xmm1);
                                                            ptr3 = *(src3 + (__int64)(__int64)ptr3*8 + 32);
                                                            a2[9] = ptr3;
                                                            a2 += 80;
                                                            a1 -= 80;
                                                            ptr3 = (struct Struct_3_t *)a3;
                                                        } while (result != a3);
                                                        if ((v2 & 1) == 0) {
                                                            if (src2 < i) JUMPOUT(0x1400bb5c6);
                                                            result = 0;
                                                            v_30 = result;
                                                            if (v2 >= 2) {
                                                                src3 = (__int64 *)v2;
                                                                src3 = (__int64 *)((__int64)(__int64)src3 >> 1);
                                                                if (v2 < 8) {
                                                                    a1 = ptr2->field_20;
                                                                    ptr->field_20 = a1;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)ptr2);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + 16));
                                                                    _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)ptr, xmm0);
                                                                    a1 =  + (__int64)(__int64)src3*8;
                                                                    a1 += (__int64)(__int64)a1*4;
                                                                    a2 = *(__int64 *)((__int64)ptr2 + (__int64)a1 + 32);
                                                                    *(__int64 *)((__int64)ptr + (__int64)a1 + 32) = a2;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)a1));
                                                                    xmm1 = _mm_loadu_si128((__m128i *)((__int64)ptr2 + (__int64)a1 + 16));
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a1 + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a1), xmm0);
                                                                    a2 = 1;
                                                                    a3 = (size_t *)v2;
                                                                    a3 = (size_t *)((__int64)a3 - (__int64)src3);
                                                                    if (a2 < src3) {
                                                                        src4 = a2 + 1;
                                                                        a1 =  + (__int64)(__int64)a2*8;
                                                                        a1 += (__int64)(__int64)a1*4;
                                                                        ptr3 = (struct Struct_3_t *)a2;
                                                                        do {
                                                                            ptr3 = (struct Struct_3_t *)((__int64)(__int64)ptr3 << 3);
                                                                            v7 = ptr3 + (__int64)(__int64)ptr3*4;
                                                                            ptr3 = (struct Struct_3_t *)src4;
                                                                            src4 = *(__int64 *)(ptr2 + v7 + 32);
                                                                            *(__int64 *)(ptr + v7 + 32) = (__int64)(src4);
                                                                            xmm0 = _mm_loadu_si128((__m128i *)(ptr2 + v7));
                                                                            xmm1 = _mm_loadu_si128((__m128i *)(ptr2 + v7 + 16));
                                                                            _mm_storeu_si128((__m128i *)(ptr + v7 + 16), xmm1);
                                                                            _mm_storeu_si128((__m128i *)(ptr + v7), xmm0);
                                                                            /* cmp ptr3 , src3 */;
                                                                            src4 = (__int64 *)ptr3;
                                                                            src4 += 0;
                                                                            a1 += 40;
                                                                        } while (ptr3 < src3);
                                                                    }
                                                                } else {
                                                                    a1 = ptr2->field_48;
                                                                    a2 = ptr2->field_98;
                                                                    src4 = 0;
                                                                    a3 = 0;
                                                                    src4 = (a1 >= ptr2->field_20) ? 1 : 0;
                                                                    a3 = (a1 < ptr2->field_20) ? 1 : 0;
                                                                    v7 = ptr2 + 80;
                                                                    ptr3 = ptr2 + 120;
                                                                    /* cmp a2 , ptr2->field_70 */;
                                                                    src = a3 + (__int64)(__int64)a3*4;
                                                                    a3 = ptr2 + (__int64)(__int64)src*8;
                                                                    src4 += (__int64)(__int64)src4*4;
                                                                    a2 = (size_t *)v7;
                                                                    if (src4 < 0) a2 = ptr3;
                                                                    a1 = ptr2 + (__int64)(__int64)src4*8;
                                                                    if (src4 < 0) ptr3 = v7;
                                                                    v7 = a2[4];
                                                                    v12 = ptr3->field_20;
                                                                    src4 = *(__int64 *)(ptr2 + (__int64)(__int64)src4*8 + 32);
                                                                    src2 = (__int64 *)a1;
                                                                    if (v12 < src4) src2 = a2;
                                                                    if (v7 < *(__int64 *)(ptr2 + (__int64)(__int64)src*8 + 32)) src2 = a3;
                                                                    if (v7 < *(__int64 *)(ptr2 + (__int64)(__int64)src*8 + 32)) a3 = a2;
                                                                    if (v7 < *(__int64 *)(ptr2 + (__int64)(__int64)src*8 + 32)) a2 = a1;
                                                                    if (v12 >= src4) a1 = ptr3;
                                                                    if (v12 < src4) a2 = ptr3;
                                                                    ptr3 = a2[4];
                                                                    ptr3 = (struct Struct_3_t *)src2;
                                                                    if (ptr3 < *(src2 + 32)) ptr3 = a2;
                                                                    if (0 /* unresolved: flags < */) a2 = src2;
                                                                    src4 = a3[4];
                                                                    ptr->field_20 = src4;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)a3);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(a3 + 16));
                                                                    _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)ptr, xmm0);
                                                                    a3 = ptr3->field_20;
                                                                    ptr->field_48 = a3;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)ptr3);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(ptr3 + 16));
                                                                    _mm_storeu_si128((__m128i *)(ptr + 56), xmm1);
                                                                    _mm_storeu_si128((__m128i *)(ptr + 40), xmm0);
                                                                    a3 = a2[4];
                                                                    ptr->field_70 = a3;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)a2);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(a2 + 16));
                                                                    _mm_storeu_si128((__m128i *)(ptr + 96), xmm1);
                                                                    _mm_storeu_si128((__m128i *)(ptr + 80), xmm0);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)a1);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)(a1 + 16));
                                                                    a2 =  + (__int64)(__int64)src3*8;
                                                                    a2 += (__int64)(__int64)a2*4;
                                                                    src4 = (__int64)ptr2 + (__int64)a2;
                                                                    a3 = *(__int64 *)((__int64)ptr2 + (__int64)a2 + 72);
                                                                    ptr3 = *(__int64 *)((__int64)ptr2 + (__int64)a2 + 152);
                                                                    v7 = 0;
                                                                    src = 0;
                                                                    v7 = (a3 >= *(__int64 *)((__int64)ptr2 + (__int64)a2 + 32)) ? 1 : 0;
                                                                    src = (a3 < *(__int64 *)((__int64)ptr2 + (__int64)a2 + 32)) ? 1 : 0;
                                                                    /* cmp ptr3 , *(__int64 *)((__int64)ptr2 + (__int64)a2 + 112) */;
                                                                    src += (__int64)(__int64)src*4;
                                                                    v7 += v7*4;
                                                                    a3 = src4 + v7*8;
                                                                    src2 = (__int64)ptr2 + (__int64)a2 + 120;
                                                                    i = (__int64)ptr2 + (__int64)a2 + 80;
                                                                    ptr3 = (struct Struct_3_t *)i;
                                                                    if (v7 < 0) ptr3 = src2;
                                                                    if (v7 < 0) src2 = i;
                                                                    v12 = *(src2 + 32);
                                                                    v7 = *(src4 + v7*8 + 32);
                                                                    i = (__int64 *)a3;
                                                                    if (v12 < v7) i = ptr3;
                                                                    result = (__int64)src3;
                                                                    src3 = ptr3->field_20;
                                                                    /* cmp src3 , *(src4 + (__int64)(__int64)src*8 + 32) */;
                                                                    src3 = (__int64 *)result;
                                                                    src4 += (__int64)(__int64)src*8;
                                                                    if (src4 < 0) i = src4;
                                                                    if (src4 < 0) src4 = ptr3;
                                                                    _mm_storeu_si128((__m128i *)(ptr + 120), xmm1);
                                                                    if (src4 < 0) ptr3 = a3;
                                                                    if (v12 >= v7) a3 = src2;
                                                                    if (v12 < v7) ptr3 = src2;
                                                                    _mm_storeu_si128((__m128i *)(ptr + 136), xmm0);
                                                                    v7 = ptr3->field_20;
                                                                    /* cmp v7 , *(i + 32) */;
                                                                    a1 = a1[4];
                                                                    v7 = (__int64)i;
                                                                    if (a1 < 0) i = ptr3;
                                                                    ptr->field_98 = a1;
                                                                    if (a1 < 0) ptr3 = i;
                                                                    a1 = *(src4 + 32);
                                                                    *(__int64 *)((__int64)ptr + (__int64)a2 + 32) = a1;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)src4);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(src4 + 16));
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2), xmm0);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)i);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(i + 16));
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 40), xmm0);
                                                                    a1 = *(i + 32);
                                                                    *(__int64 *)((__int64)ptr + (__int64)a2 + 72) = a1;
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 56), xmm1);
                                                                    xmm0 = _mm_loadu_si128((__m128i *)ptr3);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(ptr3 + 16));
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 80), xmm0);
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 96), xmm1);
                                                                    a1 = ptr3->field_20;
                                                                    *(__int64 *)((__int64)ptr + (__int64)a2 + 112) = a1;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)a3);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(a3 + 16));
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 120), xmm0);
                                                                    _mm_storeu_si128((__m128i *)((__int64)ptr + (__int64)a2 + 136), xmm1);
                                                                    a1 = a3[4];
                                                                    *(__int64 *)((__int64)ptr + (__int64)a2 + 152) = a1;
                                                                    a2 = 4;
                                                                    a3 = (size_t *)v2;
                                                                    a3 -= result;
                                                                    if (a2 < result) {
                                                                        return (__int64)a3;
                                                                    } else {
                                                                    }
                                                                }
                                                                a1 =  + (__int64)(__int64)src3*8;
                                                                ptr3 = a1 + (__int64)(__int64)a1*4;
                                                                a1 = (__int64)ptr + (__int64)ptr3;
                                                                if (a2 < a3) {
                                                                    ptr3 = (struct Struct_3_t *)((__int64)ptr3 + (__int64)ptr2);
                                                                    v7 = a2 + 1;
                                                                    src4 =  + (__int64)(__int64)a2*8;
                                                                    src4 += (__int64)(__int64)src4*4;
                                                                    do {
                                                                        a2 = (size_t *)((__int64)(__int64)a2 << 3);
                                                                        src2 = a2 + (__int64)(__int64)a2*4;
                                                                        a2 = (size_t *)v7;
                                                                        v7 = *(__int64 *)((__int64)ptr3 + (__int64)src2 + 32);
                                                                        *(__int64 *)((__int64)a1 + (__int64)src2 + 32) = v7;
                                                                        xmm0 = _mm_loadu_si128((__m128i *)((__int64)ptr3 + (__int64)src2));
                                                                        xmm1 = _mm_loadu_si128((__m128i *)((__int64)ptr3 + (__int64)src2 + 16));
                                                                        _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)src2 + 16), xmm1);
                                                                        _mm_storeu_si128((__m128i *)((__int64)a1 + (__int64)src2), xmm0);
                                                                        /* cmp a2 , a3 */;
                                                                        v7 = (__int64)a2;
                                                                        v7 += 0;
                                                                        src4 += 40;
                                                                    } while (a2 < a3);
                                                                }
                                                                a2 = v2 + v2*4;
                                                                ptr3 = ptr2 + (__int64)(__int64)a2*8;
                                                                ptr3 -= 40;
                                                                a2 = ptr + (__int64)(__int64)a2*8;
                                                                a2 -= 40;
                                                                a3 = a1 - 40;
                                                                do {
                                                                    v_38 = (__int64)src3;
                                                                    v12 = a1[4];
                                                                    src4 = 0;
                                                                    v7 = 0;
                                                                    src = (__int64 *)a1;
                                                                    v12 = (v12 >= ptr->field_20) ? 1 : 0;
                                                                    src2 = (0 /* unresolved: flags < */) ? 1 : 0;
                                                                    i = *(src + 32);
                                                                    ptr2->field_20 = i;
                                                                    xmm0 = _mm_loadu_si128((__m128i *)src);
                                                                    xmm1 = _mm_loadu_si128((__m128i *)(src + 16));
                                                                    _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
                                                                    _mm_storeu_si128((__m128i *)ptr2, xmm0);
                                                                    src3 = a2[4];
                                                                    result = a3[4];
                                                                    /* cmp src3 , result */;
                                                                    src = 0;
                                                                    src -= 1;
                                                                    i = (__int64 *)a3;
                                                                    if (src3 < result) {
                                                                        v7 = (__int64)src2;
                                                                        result = v7 + v7*4;
                                                                        a1 += result*8;
                                                                        src4 = (__int64 *)v12;
                                                                        result = src4 + (__int64)(__int64)src4*4;
                                                                        ptr += result*8;
                                                                        result = 0;
                                                                        result = 0;
                                                                        ptr2 += 40;
                                                                        src4 = *(i + 32);
                                                                        ptr3->field_20 = src4;
                                                                        xmm0 = _mm_loadu_si128((__m128i *)i);
                                                                        xmm1 = _mm_loadu_si128((__m128i *)(i + 16));
                                                                        _mm_storeu_si128((__m128i *)(ptr3 + 16), xmm1);
                                                                        _mm_storeu_si128((__m128i *)ptr3, xmm0);
                                                                        src4 = src + (__int64)(__int64)src*4;
                                                                        a2 += (__int64)(__int64)src4*8;
                                                                        result += result*4;
                                                                        a3 += result*8;
                                                                        ptr3 -= 40;
                                                                        src3 = (__int64 *)v_38;
                                                                        --src3;
                                                                        a3 += 40;
                                                                        if ((v2 & 1) != 0) {
                                                                            result = 0;
                                                                            ptr3 = 0;
                                                                            result = (ptr >= a3) ? 1 : 0;
                                                                            ptr3 = (ptr < a3) ? 1 : 0;
                                                                            src4 = (__int64 *)a1;
                                                                            if (ptr < a3) src4 = ptr;
                                                                            v7 = *(src4 + 32);
                                                                            ptr2->field_20 = v7;
                                                                            xmm0 = _mm_loadu_si128((__m128i *)src4);
                                                                            xmm1 = _mm_loadu_si128((__m128i *)(src4 + 16));
                                                                            _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm1);
                                                                            _mm_storeu_si128((__m128i *)ptr2, xmm0);
                                                                            ptr3 += (__int64)(__int64)ptr3*4;
                                                                            ptr += (__int64)(__int64)ptr3*8;
                                                                            result += result*4;
                                                                            a1 += result*8;
                                                                        }
                                                                        if (ptr != a3) JUMPOUT(0x1400bb5c1);
                                                                        a2 += 40;
                                                                        if (a1 != a2) JUMPOUT(0x1400bb5c1);
                                                                        return (__int64)a2;
                                                                    }
                                                                    i = (__int64 *)a2;
                                                                    return (__int64)i;
                                                                } while (!((src3 == 0)));
                                                                return (__int64)i;
                                                            }
                                                            return (__int64)i;
                                                        }
                                                        result = a3 + (__int64)(__int64)a3*4;
                                                        a3 = (size_t *)(~(__int64)a3);
                                                        a1 = a3 + (__int64)(__int64)a3*4;
                                                        a2 = *(src3 + (__int64)(__int64)a1*8 + 32);
                                                        *(__int64 *)(ptr2 + result*8 + 32) = (__int64)(a2);
                                                        xmm0 = _mm_loadu_si128((__m128i *)(src3 + (__int64)(__int64)a1*8));
                                                        xmm1 = _mm_loadu_si128((__m128i *)(src3 + (__int64)(__int64)a1*8 + 16));
                                                        _mm_storeu_si128((__m128i *)(ptr2 + result*8 + 16), xmm1);
                                                        _mm_storeu_si128((__m128i *)(ptr2 + result*8), xmm0);
                                                        return _mm_cvtsi128_si64(xmm1);
                                                    }
                                                    a3 = 0;
                                                    src = (__int64 *)v_38;
                                                    return (__int64)src;
                                                }
                                                return (__int64)src;
                                            }
                                            a2 -= 40;
                                            a3 = i + (__int64)(__int64)i*4;
                                            ptr3 = a1[4];
                                            *(__int64 *)(ptr + (__int64)(__int64)a3*8 + 32) = (__int64)(ptr3);
                                            xmm0 = _mm_loadu_si128((__m128i *)a1);
                                            xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
                                            _mm_storeu_si128((__m128i *)(ptr + (__int64)(__int64)a3*8 + 16), xmm1);
                                            _mm_storeu_si128((__m128i *)(ptr + (__int64)(__int64)a3*8), xmm0);
                                            ++i;
                                            a1 += 40;
                                            src = src2;
                                        } while (true);
                                    }
                                    if (src2 < v2) JUMPOUT(0x1400bb58a);
                                    result = v2 + v2*4;
                                    a1 = ptr2 + result*8;
                                    result = rsp + 128;
                                    v_28 = result;
                                    src = (__int64 *)v_38;
                                    v_20 = src;
                                    sub_1400BAB00(a1, a2, ptr);
                                    src2 = (__int64 *)v2;
                                    return (__int64)src2;
                                }
                                result = v2 + v2*4;
                                result = ptr2 + result*8;
                                a1 = v2 + 1;
                                if (src2 != a1) {
                                    a1 = a2;
                                    a1 = (size_t *)((__int64)(__int64)a1 & -2);
                                    a3 = (size_t *)v_40;
                                    a3 += (__int64)(__int64)i*8;
                                    ptr3 = (struct Struct_3_t *)result;
                                    v7 = 0;
                                    i = 0x1FFFFFFFFFFFFFFE;
                                    do {
                                        src4 = a3[4];
                                        ptr3->field_20 = src4;
                                        xmm0 = _mm_loadu_si128((__m128i *)a3);
                                        xmm1 = _mm_loadu_si128((__m128i *)(a3 + 16));
                                        _mm_storeu_si128((__m128i *)(ptr3 + 16), xmm1);
                                        _mm_storeu_si128((__m128i *)ptr3, xmm0);
                                        src4 = v7 + 2;
                                        v7 ^= (__int64)i;
                                        v7 += v7*4;
                                        xmm0 = _mm_loadu_si128((__m128i *)(src3 + v7*8));
                                        xmm1 = _mm_loadu_si128((__m128i *)(src3 + v7*8 + 16));
                                        _mm_storeu_si128((__m128i *)(ptr3 + 40), xmm0);
                                        _mm_storeu_si128((__m128i *)(ptr3 + 56), xmm1);
                                        v7 = *(src3 + v7*8 + 32);
                                        ptr3->field_48 = v7;
                                        ptr3 += 80;
                                        a3 -= 80;
                                        v7 = (__int64)src4;
                                    } while (a1 != src4);
                                    if (((__int64)a2 & 1) == 0) {
                                        return v7;
                                    }
                                    a1 = src4 + (__int64)(__int64)src4*4;
                                    src4 = (__int64 *)(~(__int64)src4);
                                    a3 = src4 + (__int64)(__int64)src4*4;
                                    ptr3 = *(src3 + (__int64)(__int64)a3*8 + 32);
                                    v_20[(__int64)a1] = ptr3;
                                    xmm0 = _mm_loadu_si128((__m128i *)(src3 + (__int64)(__int64)a3*8));
                                    xmm1 = _mm_loadu_si128((__m128i *)(src3 + (__int64)(__int64)a3*8 + 16));
                                    _mm_storeu_si128((__m128i *)(result + (__int64)(__int64)a1*8 + 16), xmm1);
                                    _mm_storeu_si128((__m128i *)(result + (__int64)(__int64)a1*8), xmm0);
                                    return _mm_cvtsi128_si64(xmm1);
                                }
                                src4 = 0;
                                return (__int64)src4;
                            }
                            a3 = v2 + v2*4;
                            ptr3 = a1[4];
                            *(a2 + (__int64)(__int64)a3*8 - 8) = ptr3;
                            xmm0 = _mm_loadu_si128((__m128i *)a1);
                            xmm1 = _mm_loadu_si128((__m128i *)(a1 + 16));
                            _mm_storeu_si128((__m128i *)(a2 + (__int64)(__int64)a3*8 - 24), xmm1);
                            _mm_storeu_si128((__m128i *)(a2 + (__int64)(__int64)a3*8 - 40), xmm0);
                            a2 -= 40;
                            a1 += 40;
                            a3 = (size_t *)src2;
                        } while (true);
                    }
                    a1 = (size_t *)v_30;
                    a1 = a1[4];
                    if (a1 >= arg_20) {
                        return (__int64)a1;
                    }
                    return (__int64)a1;
                }
                a1 = ptr2->field_20;
                a2 = (size_t *)arg_20;
                ptr3 = (a1 < a2) ? 1 : 0;
                src4 = a3[4];
                a1 = (a1 < src4) ? 1 : 0;
                a1 = (size_t *)((__int64)(__int64)a1 ^ (__int64)ptr3);
                a2 = (a2 < src4) ? 1 : 0;
                a2 = (size_t *)((__int64)(__int64)a2 ^ (__int64)ptr3);
                if (a2 != 0) result = a3;
                if (a1 != 0) result = ptr2;
                return (__int64)a2;
            }
            v_20 = 1;
            sub_1400BA460(ptr2, src2, ptr, v12);
            return (__int64)v_20;
        } while (v2 >= 33);
        return (__int64)v_20;
    }
    return result;
}