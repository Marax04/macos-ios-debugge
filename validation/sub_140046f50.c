// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[8];
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

__int64 sub_14002EDF0();
__int64 sub_140047CAA();
__int64 sub_1400471B2();
__int64 sub_1400F27F6();

__int64 __fastcall sub_140046F50(__int64 a1, int *a2, __int64 a3) {
    __int64 rsp;
    int arg_160;
    int arg_272;
    __int64 v_28;
    int v_30;
    int v_38;
    __int64 v_40;
    int v_50;
    int v_d0;
    int v_e0;
    __int64 *dst;
    struct Struct_1_t *ptr;
    __int64 *dst2;
    __int64 i;
    __int64 *dst3;
    __int64 v9;
    __int64 v1;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v3;
    __int64 v8;

    dst = (__int64 *)a3;
    ptr = (struct Struct_1_t *)a2;
    dst2 = a2[4];
    if (dst2 == 0) {
        i = a1;
        dst3 = ptr->field_18;
        sub_14002EDF0(0, 632);
        if (v1 == 0) JUMPOUT(0x140047cea);
        dst2 = (__int64 *)v1;
        arg_160 = 0;
        arg_272 = 0;
        *dst3 = v1;
        *(dst3 + 8) = 0;
        v9 = arg_272;
        if (v9 >= 11) JUMPOUT(0x140047cf9);
        *(dst2 + 626) = v1;
        v1 =  + v9*2;
        v1 += v9;
        a1 = ptr->field_10;
        *(dst2 + v1*8 + 376) = a1;
        xmm0 = _mm_loadu_si128((__m128i *)ptr);
        _mm_storeu_si128((__m128i *)(dst2 + v1*8 + 360), xmm0);
        v1 = v9;
        v1 <<= 5;
        xmm0 = _mm_loadu_si128((__m128i *)dst);
        xmm1 = _mm_loadu_si128((__m128i *)(dst + 16));
        _mm_storeu_si128((__m128i *)(dst2 + v1 + 16), xmm1);
        _mm_storeu_si128((__m128i *)(dst2 + v1), xmm0);
        v3 = 0;
        return sub_140047CAA();
    } else {
        dst3 = ptr->field_18;
        v3 = ptr->field_28;
        v1 = ptr->field_30;
        i = *(dst2 + 626);
        v_50 = a1;
        v_28 = (__int64)dst;
        if (i >= 11) {
            i = rsp + 376;
            a2 = rsp + 384;
            v9 = 4;
            if (v1 >= 5) JUMPOUT(0x140047168);
            v_30 = (int)a2;
            v_38 = v1;
            return sub_1400471B2();
        } else {
            v9 = v1;
            v8 = v1 + 1;
            v1 += v1*2;
            dst = dst2 + v1*8;
            dst += 360;
            if (v8 <= i) {
                v1 = dst2 + 360;
                a1 = v8 + v8*2;
                a1 = v1 + a1*8;
                v_40 = (__int64)dst3;
                dst3 = (__int64 *)i;
                dst3 -= v9;
                v1 =  + (__int64)(__int64)dst3*8;
                a3 = v1 + v1*2;
                sub_1400F27F6(a1, dst, a3);
                xmm0 = _mm_loadu_si128((__m128i *)ptr);
                _mm_storeu_si128((__m128i *)dst, xmm0);
                v1 = ptr->field_10;
                *(dst + 16) = v1;
                v1 = v_28;
                xmm0 = _mm_loadu_si128((__m128i *)v1);
                xmm1 = _mm_loadu_si128((__m128i *)(v1 + 16));
                _mm_store_si128((__m128i *)&v_e0, xmm1);
                _mm_store_si128((__m128i *)&v_d0, xmm0);
                a2 = (int *)v9;
                a2 = (int *)((__int64)(__int64)a2 << 5);
                a2 = (int *)((__int64)a2 + (__int64)dst2);
                v8 <<= 5;
                v8 += (__int64)dst2;
                dst3 = (__int64 *)((__int64)(__int64)dst3 << 5);
                dst3 = (__int64 *)v_40;
                sub_1400F27F6(v8, a2, dst3);
            } else {
                v1 = ptr->field_10;
                *(dst + 16) = v1;
                xmm0 = _mm_loadu_si128((__m128i *)ptr);
                _mm_storeu_si128((__m128i *)dst, xmm0);
                v1 = v_28;
                xmm0 = _mm_loadu_si128((__m128i *)v1);
                xmm1 = _mm_loadu_si128((__m128i *)(v1 + 16));
                _mm_store_si128((__m128i *)&v_e0, xmm1);
                _mm_store_si128((__m128i *)&v_d0, xmm0);
            }
            ++i;
            v1 = v9;
            v1 <<= 5;
            xmm0 = _mm_load_si128((__m128i *)&v_d0);
            xmm1 = _mm_load_si128((__m128i *)&v_e0);
            _mm_storeu_si128((__m128i *)(dst2 + v1 + 16), xmm1);
            _mm_storeu_si128((__m128i *)(dst2 + v1), xmm0);
            *(dst2 + 626) = i;
            i = v_50;
            return sub_140047CAA();
        }
    }
}