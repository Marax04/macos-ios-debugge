// inferred from 10 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    int field_10; // offset 16
    int field_14; // offset 20
    __int64 field_18; // offset 24
    char _pad_18[12];
    __int64 field_2C; // offset 44
    int field_34; // offset 52
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
    char _pad_40[4];
    int field_4C; // offset 76
    __int64 field_50; // offset 80
};

__int64 off_140108160();
__int64 off_140108168();
__int64 off_140108060();

__int64 __fastcall sub_140030980(int *a1, int a2) {
    int v_10;
    int v_14;
    int v_18;
    int v_1c;
    int v_20;
    int v_24;
    int v_28;
    int v_30;
    int v_3c;
    int v_4;
    int v_40;
    int v_8;
    char *str;
    __int64 v4;
    struct Struct_1_t *ptr;
    __m128i xmm0;
    __int64 result;
    __int64 v5;
    __int64 v6;
    __int64 v8;
    __int64 xmm1;
    __int64 v2;
    __int64 v9;

    v4 = v9;
    ptr = (struct Struct_1_t *)a1;
    xmm0 = _mm_setzero_si128();
    _mm_store_si128((__m128i *)&v_20, xmm0);
    _mm_store_si128((__m128i *)&v_30, xmm0);
    _mm_store_si128((__m128i *)&v_40, xmm0);
    v_10 = 0;
    a2 = str - 64;
    off_140108160(v4, a2);
    if (result != 0) {
        a1 = (int *)v_40;
        result = 0;
        if (((__int64)a1 & 0x400) != 0) {
            v_8 = 0;
            v5 = str - 8;
            off_140108168(v4, 9, v5, 8);
            if (result == 0) {
                off_140108060(a1, a2, v5, v6);
                result <<= 32;
                result |= 2;
                ptr->field_8 = result;
                *(__int64 *)ptr = (__int64)(2);
            } else {
                result = v_8;
                result <<= 21;
                result >>= 31;
                result &= v_4;
                a1 = (int *)v_40;
                v5 = v_1c;
                a2 = v_20;
                a2 <<= 32;
                a2 |= v5;
                v5 = v_28;
                v6 = v_24;
                v8 = v_14;
                v8 <<= 32;
                v8 |= v_10;
                *(__int64 *)ptr = (__int64)(1);
                ptr->field_8 = v8;
                ptr->field_10 = 1;
                ptr->field_14 = v6;
                ptr->field_18 = 1;
                xmm0 = _mm_loadu_si128((__m128i *)&v_3c);
                xmm0 = _mm_shuffle_epi32(xmm0, 144);
                xmm1 = v_18;
                xmm0 = _mm_cvtsi64_si128((__int64)(xmm1));
                _mm_storeu_si128((__m128i *)(ptr + 28), xmm0);
                v2 = v_30;
                ptr->field_2C = v2;
                ptr->field_34 = v5;
                ptr->field_38 = a2;
                ptr->field_40 = 0;
                ptr->field_4C = a1;
                ptr->field_50 = result;
            }
            return v2;
        }
        return v2;
    }
    return result;
}