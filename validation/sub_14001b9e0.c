// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[2056];
    __int64 field_808; // offset 0x808
    __int64 field_810; // offset 0x810
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[2048];
    __int64 field_810; // offset 0x810
};

__int64 sub_1400F1D90();
__int64 sub_1400F27F0();
__int64 sub_14002EDF0();
__int64 sub_14001BB0C();
extern __int64 off_140110058;
extern __int64 off_140110048;

__int64 __fastcall sub_14001B9E0(__int64 *a1) {
    __int64 rsp;
    char *str;
    char *str2;
    struct Struct_2_t *ptr;
    __int64 *src;
    struct Struct_1_t *result;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v3;
    __int64 v6;
    __int64 v4;

    sub_1400F1D90(0x1030);
    ptr = *a1;
    if (ptr != 0) {
        if (ptr->field_810 == 0) JUMPOUT(0x14001bb40);
        src = ptr->field_8;
        result = 96;
        xmm0 = _mm_loadu_si128((__m128i *)&off_140110058);
        xmm1 = _mm_loadu_si128((__m128i *)&off_140110048);
        do {
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 40), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 56), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 24), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 8), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 8), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 24), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 40), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 56), xmm0);
            result += 128;
        } while (result != 0x860);
        v3 = ptr + 16;
        sub_1400F27F0(str2, v3, 0x808);
        sub_1400F27F0(v3, str, 0x800);
        ptr->field_810 = 0;
        *(__int64 *)rsp = *(__int64 *)rsp | 0;
        v6 = *(src + 384);
        sub_14002EDF0(0, 0x818);
        if (result == 0) JUMPOUT(0x14001bb5e);
        v4 = (__int64)result;
        sub_1400F27F0(result, str2, 0x808);
        result->field_808 = v6;
        result->field_810 = 0;
        return sub_14001BB0C();
    } else {
        return (__int64)result;
    }
}