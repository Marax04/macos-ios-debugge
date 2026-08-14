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

__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
__int64 sub_1400F3340();
__int64 sub_14001C012();
extern __int64 off_140110058;
extern __int64 off_140110048;
extern __int64 off_14012D260;
extern __int64 off_14001C080;

__int64 __fastcall sub_14001BEA0(int *a1) {
    __int64 rsp;
    char *str;
    __int64 *src;
    __int64 result;
    __m128i xmm0;
    __m128i xmm1;
    struct Struct_1_t *ptr;
    __int64 *dst;
    __int64 v9;
    __int64 v5;
    __int64 v6;
    __int64 v7;
    __int64 v8;

    *a1 = *a1 + 1;
    if ((*a1 <= 0)) {
    } else {
        src = (__int64 *)a1;
        result = 96;
        xmm0 = _mm_loadu_si128((__m128i *)&off_140110058);
        xmm1 = _mm_loadu_si128((__m128i *)&off_140110048);
        do {
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 48), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 64), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 32), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 16), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 16), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 32), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 48), xmm0);
            result += 128;
        } while (result != 0x860);
        sub_14002EDF0(0, 0x980);
        if (result != 0) {
            ptr = (struct Struct_1_t *)result;
            ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & -128);
            dst = ptr + 128;
            ptr->field_78 = result;
            ptr->field_80 = 0;
            ptr->field_88 = src;
            v9 = ptr + 144;
            sub_1400F27F0(v9, str, 0x800);
            xmm0 = _mm_setzero_si128();
            _mm_store_si128((__m128i *)(ptr + 0x890), xmm0);
            ptr->field_8A0 = 1;
            ptr->field_8A8 = 0;
            ptr->field_900 = 0;
            v5 = *(src + 512);
            ptr->field_80 = v5;
            /* cmpxchg %(__int64)dst, 512(%(__int64)src) */;
            if (!((0 /* unresolved: flags == */))) {
                do {
                    *dst = v5;
                    /* cmpxchg %(__int64)dst, 512(%(__int64)src) */;
                } while ((0 /* unresolved: flags != */));
            }
            v6 = (__int64)dst;
            return result;
        }
    }
    sub_1400F3340(128, 0x900);
    v7 = off_14012D260;
    if (v7 == 0) JUMPOUT(0x14001bff1);
    if (result < 0) JUMPOUT(0x14001c00b);
    v8 = &off_14001C080;
    return sub_14001C012();
}