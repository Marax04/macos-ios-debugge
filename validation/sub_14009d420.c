// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[52];
    __int64 field_3C; // offset 60
};

__int64 sub_14009D4A6();

__int64 __fastcall sub_14009D420(__int64 *a1, __int64 *a2) {
    int v_130;
    __int64 v4;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v6;
    int v1;
    __int64 v8;
    __int64 v7;
    __int64 v3;
    __m128i xmm6;

    _mm_store_si128((__m128i *)&v_130, xmm6);
    v4 = a2[2];
    if (v4 >= 64) {
        ptr = *(a2 + 8);
        if (ptr->field_0 != 0x5A4D) JUMPOUT(0x14009d4a0);
        v2 = ptr->field_3C;
        v6 = v2 + 24;
        if (v4 >= v6) {
            if (*(__int64 *)(ptr + v2) != 0x4550) JUMPOUT(0x14009d4f1);
            v1 = *(__int64 *)(ptr + v2 + 4);
            if (v1 != 0x8664) JUMPOUT(0x14009d4f9);
            v8 = *(__int64 *)(ptr + v2 + 20);
            v7 = v6 + v8;
            if (v4 >= v7) {
                v3 = v2 + 26;
                if (v3 <= v4) JUMPOUT(0x14009d505);
                *(a1 + 8) = 0;
                return sub_14009D4A6();
            }
        }
    }
    *(a1 + 8) = 0;
    return sub_14009D4A6();
}