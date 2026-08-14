// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[40];
    __int64 field_30; // offset 48
};

__int64 sub_14002DAE0();
__int64 sub_14002D9A0();

__int64 __fastcall sub_14002FC30(__int64 *a1,struct Struct_1_t *a2, size_t a3, __int64 a4) {
    int arg_30;
    int v_48;
    int v_8;
    char *str;
    __int64 v7;
    __int64 v4;
    int v9;
    __int64 v2;
    __int64 result;
    __int64 v3;
    struct Struct_2_t *ptr;
    __int64 *dst;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;
    __m128i xmm2;

    v7 = ((__int64 *)a2)[7];
    if (v7 != 3) {
        v4 = str - 64;
        v9 = ((__int64 *)a2)[2];
        v2 = a2->field_0;
        a3 = ((__int64 *)a2)[7];
        a4 = (a3 == 3) ? 1 : 0;
        result = (v7 > a3) ? 1 : 0;
        v3 = a2->field_8;
        result |= a4;
        if ((((__int64 *)a2)[7] & 1) == 0) JUMPOUT(0x14002fd54);
        if (result == 0) {
            do {
                if (a3 == 0) JUMPOUT(0x14002fed7);
                result = a3;
                if (a3 == 1) JUMPOUT(0x14002fd61);
                v_8 = v2;
                ptr = (struct Struct_2_t *)a1;
                dst = (__int64 *)a2;
                sub_14002DAE0(a2, a2, a3, a4);
                if (v3 <= result) JUMPOUT(0x14002fd2f);
                v6 = str - 72;
                sub_14002D9A0(v6, dst);
                v7 = arg_30;
                result = v3;
                ptr->field_30 = v7;
                xmm0 = _mm_loadu_si128((__m128i *)v4);
                xmm1 = _mm_loadu_si128((__m128i *)(v4 + 16));
                xmm2 = _mm_loadu_si128((__m128i *)(v4 + 32));
                _mm_storeu_si128((__m128i *)(ptr + 32), xmm2);
                _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
                _mm_storeu_si128((__m128i *)ptr, xmm0);
                result -= v_48;
                if ((result < 0)) JUMPOUT(0x14002ffa6);
                a1 = (__int64 *)ptr;
                a2 = (struct Struct_1_t *)dst;
                *(dst + 8) = result;
                a3 = 2;
                v2 = v_8;
                if (ptr->field_0 == 10) {
                    v3 = result;
                    *a1 = 10;
                }
                return v3;
            } while (v7 <= a3);
            return v3;
        }
    }
    return result;
}