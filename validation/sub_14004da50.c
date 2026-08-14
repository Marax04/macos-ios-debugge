// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char _pad_start[352];
    __int64 field_160; // offset 352
    char _pad_160[8];
    __int64 field_170; // offset 368
};

// inferred from 5 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[168];
    __int64 field_A8; // offset 168
    char _pad_A8[168];
    __int64 field_158; // offset 344
    __int64 field_160; // offset 352
    __int64 field_168; // offset 360
    __int64 field_170; // offset 368
};

__int64 sub_1400F27F0();
__int64 sub_14004DBFD();
__int64 sub_140046040();
__int64 sub_140046190();
__int64 sub_1400462A0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14004DA50(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int arg_8;
    int v_38;
    int v_500;
    int v_68;
    int v_6c0;
    int v_6d0;
    int v_70;
    int v_78;
    struct Struct_2_t *ptr;
    __int64 *src;
    __int64 result;
    __int64 v6;
    __int64 v5;
    __int64 v2;
    __m128i xmm6;
    __m128i xmm7;

    _mm_store_si128((__m128i *)&v_6d0, xmm7);
    _mm_store_si128((__m128i *)&v_6c0, xmm6);
    ptr = (struct Struct_2_t *)a2;
    v_68 = 0;
    v_70 = 1;
    v_78 = 0;
    src = a2->field_160;
    if (src != a2->field_170) {
        result = src + 328;
        ptr->field_160 = result;
        v6 = *src;
        if (v6 != 12) {
            v_38 = (int)a1;
            a2 = src + 176;
            src += 8;
            a1 = rsp + 0x4E8;
            sub_1400F27F0(a1, a2, 144);
            a1 = rsp + 192;
            sub_1400F27F0(a1, src, 168);
            v5 = v_500;
            a1 = 0x8000000000000003;
            if (v5 != a1) {
                a1 = 0x8000000000000002;
                if (v5 >= a1) JUMPOUT(0x14004dbf0);
            }
            src = 0;
            return sub_14004DBFD();
        }
    }
    arg_8 = 6;
    a1[2] = 0;
    a1[4] = 0;
    *a1 = 2;
    src = 1;
    if (v_68 != 0) {
        off_140108030();
        off_140108038(result, 0, src);
    }
    a1 = ptr->field_160;
    v2 = ptr->field_170;
    v2 -= (__int64)a1;
    v2 >>= 3;
    a2 = 0x8F9C18F9C18F9C19;
    a2 = (struct Struct_1_t *)((__int64)(__int64)(__int64)a2 * v2);
    sub_140046040(a1, a2);
    if (ptr->field_168 != 0) {
        src = ptr->field_158;
        off_140108030();
        off_140108038(v2, 0, src);
    }
    if (ptr->field_A8 != 12) {
        src = ptr + 168;
        ptr += 24;
        sub_140046190(ptr);
        sub_1400462A0(src);
    }
    xmm6 = _mm_load_si128((__m128i *)&v_6c0);
    xmm7 = _mm_load_si128((__m128i *)&v_6d0);
    return result;
}