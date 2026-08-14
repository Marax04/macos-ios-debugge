// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    __int16 field_0; // offset 0
    __int16 field_2; // offset 2
    __int16 field_4; // offset 4
    int field_6; // offset 6
    __int16 field_A; // offset 10
    __int64 field_C; // offset 12
};

__int64 sub_1400361B0();

__int64 __fastcall sub_1400360D0(__int64 *a1, __int64 *a2, __int64 *a3, int a4) {
    __int64 v1;
    struct Struct_1_t *ptr;
    __int64 v2;
    __m128i xmm0;

    a3 = a2;
    v1 = a2[2];
    if (v1 <= 260) {
        if (v1 <= 6) JUMPOUT(0x14003618c);
        ptr = *(a3 + 8);
        if (ptr->field_0 != 92) JUMPOUT(0x14003618c);
        if (ptr->field_2 != 92) JUMPOUT(0x14003618c);
        if (ptr->field_4 != 63) JUMPOUT(0x14003618c);
        a4 = ptr->field_6;
        if (a4 != 92) JUMPOUT(0x14003618c);
        if (ptr->field_A != 58) JUMPOUT(0x140036148);
        if (ptr->field_C != 92) JUMPOUT(0x140036148);
        ptr += 8;
        return sub_1400361B0();
    } else {
        v2 = a3[2];
        a1[2] = v2;
        xmm0 = _mm_loadu_si128((__m128i *)a3);
        _mm_storeu_si128((__m128i *)a1, xmm0);
        return _mm_cvtsi128_si64(xmm0);
    }
}