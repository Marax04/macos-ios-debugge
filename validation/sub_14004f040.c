// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F27F0();
__int64 sub_14004CFC0();
__int64 sub_1400F6010();
__int64 sub_140045D80();
__int64 sub_140046740();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14004F040(__int64 a1, __int64 *a2) {
    __int64 rsp;
    __int64 arg_8;
    int v_108;
    __int64 v_110;
    int v_117;
    int v_11f;
    int v_127;
    int v_1c0;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_5f;
    int v_70;
    int v_7f;
    int v_90;
    int v_9f;
    int v_b0;
    int v_b8;
    int v_d8;
    int v_e8;
    int v_f8;
    char *str;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 result;
    __int64 *dst;
    int v9;
    __int64 v4;
    __int64 i;
    __int64 v7;
    __int64 v5;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;

    ptr = (struct Struct_1_t *)a2;
    v_48 = a1;
    v_30 = 0;
    v_38 = 8;
    v_40 = 0;
    src = (__int64 *)arg_8;
    result = a2[3];
    v_28 = result;
    dst = 8;
    v9 = 1;
    v4 = rsp + 185;
    i = 0;
    if (src != v_28) {
        v7 = src + 176;
        v5 = (__int64)ptr;
        ptr->field_8 = v7;
        ptr = *src;
        while (ptr != 12) {
            a2 = src + 8;
            a1 = rsp + 280;
            sub_1400F27F0(a1, a2, 168);
            v_110 = (__int64)ptr;
            v_1c0 = 0;
            a1 = rsp + 176;
            a2 = rsp + 272;
            sub_14004CFC0(a1, a2);
            result = v_b0;
            ptr = (struct Struct_1_t *)v_b8;
            xmm0 = _mm_loadu_si128((__m128i *)v4);
            xmm1 = _mm_loadu_si128((__m128i *)(v4 + 15));
            _mm_store_si128((__m128i *)&v_70, xmm0);
            _mm_storeu_si128((__m128i *)&v_7f, xmm1);
            if (result == 2) {
                xmm0 = _mm_load_si128((__m128i *)&v_70);
                _mm_store_si128((__m128i *)&v_50, xmm0);
                xmm0 = _mm_loadu_si128((__m128i *)&v_7f);
                _mm_storeu_si128((__m128i *)&v_5f, xmm0);
                if (ptr != 7) {
                    xmm0 = _mm_loadu_si128((__m128i *)&v_5f);
                    _mm_storeu_si128((__m128i *)&v_9f, xmm0);
                    xmm0 = _mm_load_si128((__m128i *)&v_50);
                    _mm_store_si128((__m128i *)&v_90, xmm0);
                    if (i == v_30) {
                        a1 = rsp + 48;
                        sub_1400F6010(a1);
                        dst = (__int64 *)v_38;
                    }
                    *(__int64 *)((__int64)dst + (__int64)str - 1) = ptr;
                    xmm0 = _mm_load_si128((__m128i *)&v_90);
                    _mm_storeu_si128((__m128i *)&*(__int64 *)((__int64)dst + (__int64)str), xmm0);
                    xmm0 = _mm_loadu_si128((__m128i *)&v_9f);
                    _mm_storeu_si128((__m128i *)&*(__int64 *)((__int64)dst + (__int64)str + 15), xmm0);
                    ++i;
                    v_40 = i;
                    src = (__int64 *)v7;
                    ptr = (struct Struct_1_t *)v5;
                    src = ptr->field_8;
                    result = v_40;
                    v_127 = result;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_30);
                    _mm_storeu_si128((__m128i *)&v_117, xmm0);
                    a2 = (__int64 *)v_48;
                    arg_8 = 5;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_110);
                    result = v_11f;
                    a1 = v_127;
                    _mm_storeu_si128((__m128i *)(a2 + 9), xmm0);
                    a2[3] = result;
                    a2[4] = a1;
                    *a2 = 2;
                    result = v_28;
                    result -= (__int64)src;
                    result >>= 4;
                    a2 = 0x2E8BA2E8BA2E8BA3;
                    a2 = (__int64 *)((__int64)(__int64)(__int64)a2 * result);
                    sub_140045D80(src, a2);
                    if (ptr->field_10 != 0) {
                        do {
                            ptr = ptr->field_0;
                            off_140108030();
                            a1 = result;
                            a2 = 0;
                            JUMPOUT(off_140108038);
                            a1 = v_108;
                            a2 = (__int64 *)v_48;
                            a2[11] = a1;
                            xmm0 = _mm_loadu_si128((__m128i *)&v_d8);
                            xmm1 = _mm_loadu_si128((__m128i *)&v_e8);
                            xmm2 = _mm_loadu_si128((__m128i *)&v_f8);
                            _mm_storeu_si128((__m128i *)(a2 + 72), xmm2);
                            _mm_storeu_si128((__m128i *)(a2 + 56), xmm1);
                            _mm_storeu_si128((__m128i *)(a2 + 40), xmm0);
                            xmm0 = _mm_load_si128((__m128i *)&v_70);
                            _mm_store_si128((__m128i *)&v_50, xmm0);
                            xmm0 = _mm_loadu_si128((__m128i *)&v_7f);
                            _mm_storeu_si128((__m128i *)&v_5f, xmm0);
                            xmm0 = _mm_loadu_si128((__m128i *)&v_5f);
                            _mm_storeu_si128((__m128i *)(a2 + 24), xmm0);
                            xmm0 = _mm_load_si128((__m128i *)&v_50);
                            _mm_storeu_si128((__m128i *)(a2 + 9), xmm0);
                            *a2 = result;
                            arg_8 = (__int64)ptr;
                            if (i == 0) {
                                ptr = (struct Struct_1_t *)v5;
                                if (v_30 == 0) {
                                    result = v_28;
                                    result -= v7;
                                    result >>= 4;
                                    a2 = 0x2E8BA2E8BA2E8BA3;
                                    a2 = (__int64 *)((__int64)(__int64)(__int64)a2 * result);
                                    sub_140045D80(v7, a2);
                                    return (__int64)a2;
                                }
                                off_140108030();
                                ((__int64 (*)())off_140108038)(result, 0, dst);
                                return (__int64)a2;
                            }
                            v4 = (__int64)dst;
                            do {
                                sub_140046740(v4, a2, ptr);
                                v4 += 32;
                                --i;
                            } while ((i != 0));
                            return i;
                        } while (ptr->field_10 != 0);
                    }
                    return i;
                }
                src += 176;
                ptr = (struct Struct_1_t *)v5;
                return (__int64)ptr;
            }
            return (__int64)ptr;
        }
        return (__int64)ptr;
    }
    return result;
}