// inferred from 7 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
    char _pad_18[88];
    __int64 field_78; // offset 120
    char _pad_78[48];
    __int64 field_B0; // offset 176
    __int64 field_B8; // offset 184
    __int64 field_C0; // offset 192
    __int64 field_C8; // offset 200
};

__int64 sub_14008C400();
__int64 sub_14001F3F0();
__int64 sub_14008C459();
__int64 sub_14001F160();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14008C2D6() {
    int v_20;
    int v_30;
    int v_c0;
    int v_d0;
    int v_e0;
    int v_f0;
    __int64 *result;
    __m128i xmm1;
    __int64 *dst;
    __m128i xmm0;
    __int64 *src;
    __int64 v4;
    __m128i xmm6;
    __int64 v8;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v10;
    __int64 v11;
    __int64 v9;
    __int64 *dst2;

    result = 0;
    *result = *result + (__int64)result;
    xmm1 = _mm_load_si128((__m128i *)&v_c0);
    _mm_store_si128((__m128i *)&v_e0, xmm1);
    _mm_store_si128((__m128i *)&v_d0, xmm0);
    dst = ptr + 120;
    _mm_store_si128((__m128i *)&v_20, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm1);
    sub_14008C400(dst);
    ptr->field_78 = 1;
    _mm_storeu_si128((__m128i *)(ptr + 128), xmm6);
    xmm0 = _mm_load_si128((__m128i *)&v_20);
    xmm1 = _mm_load_si128((__m128i *)&v_30);
    _mm_storeu_si128((__m128i *)(ptr + 144), xmm0);
    _mm_storeu_si128((__m128i *)(ptr + 160), xmm1);
    src = ptr->field_B0;
    dst = *src;
    if (ptr->field_C8 == 0) {
        v4 = ptr->field_C0;
        result = 3;
        { __int64 __xchg_tmp = ptr->field_B8; ptr->field_B8 = src; src = __xchg_tmp; };
        if (src == 2) {
            dst += 472;
            xmm6 = _mm_load_si128((__m128i *)&v_f0);
            return sub_14001F3F0();
        }
    } else {
        *dst = *dst + 1;
        if ((*dst <= 0)) {
            v8 = *dst;
            if (v8 == 0) JUMPOUT(0x14008c50c);
            ptr = (struct Struct_1_t *)dst;
            if (result != 1) JUMPOUT(0x14008c4c3);
            v2 = ptr->field_18;
            if (v2 == 0) JUMPOUT(0x14008c473);
            v10 = ptr->field_8;
            v10 += 24;
            v11 = off_140108030;
            v9 = off_140108038;
            return sub_14008C459();
        } else {
            dst2 = *src;
            v4 = ptr->field_C0;
            result = 3;
            { __int64 __xchg_tmp = ptr->field_B8; ptr->field_B8 = src; src = __xchg_tmp; };
            if (src == 2) {
                dst = dst2 + 472;
                sub_14001F3F0(dst, v4);
            }
            *dst2 = *dst2 - 1;
            if (!((*dst2 != 0))) {
                dst = dst2;
                xmm6 = _mm_load_si128((__m128i *)&v_f0);
                return sub_14001F160();
            }
        }
    }
    xmm6 = _mm_load_si128((__m128i *)&v_f0);
    return (__int64)result;
}