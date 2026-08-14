// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[112];
    __int64 field_80; // offset 128
};

// inferred from 4 accesses on `ptr3`
struct Struct_3_t {
    char _pad_start[120];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
    char _pad_88[112];
    __int64 field_100; // offset 256
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_1400F3326();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14001ECE0(int *a1) {
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v2;
    struct Struct_3_t *ptr3;
    __int64 v11;
    __m128i xmm0;
    struct Struct_2_t *ptr2;
    __int64 v10;
    __int64 v9;
    int v3;
    __int64 v6;
    __int64 *dst;

    ptr = (struct Struct_1_t *)a1;
    sub_14002EDF0(0, 0x400);
    if (dst != 0) {
        v5 = (__int64)dst;
        sub_14002EDF0(0, 16);
        if (dst == 0) {
            sub_1400F3340(8, 16);
            sub_1400F3326(8, 0x400);
        } else {
            v2 = (__int64)dst;
            *dst = v5;
            *(dst + 8) = 64;
            sub_14002EDF0(0, 512);
            if (dst != 0) {
                ptr3 = (struct Struct_3_t *)dst;
                ptr3 = (struct Struct_3_t *)((__int64)(__int64)ptr3 & -128);
                v11 = ptr3 + 128;
                ptr3->field_78 = dst;
                ptr3->field_80 = 1;
                ptr3->field_88 = 1;
                ptr3->field_100 = v2;
                xmm0 = _mm_setzero_si128();
                _mm_store_si128((__m128i *)(ptr3 + 384), xmm0);
                *(__int64 *)ptr = (__int64)(v11);
                ptr->field_8 = v5;
                ptr->field_10 = 64;
                ptr->field_18 = 0;
                return _mm_cvtsi128_si64(xmm0);
            }
        }
        sub_1400F3340(128, 384);
        ptr2 = *a1;
        ptr = ptr2->field_80;
        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr & -8);
        if (ptr->field_8 != 0) {
            v10 = ptr->field_0;
            off_140108030();
            ((__int64 (*)())off_140108038)(dst, 0, v10);
        }
        off_140108030();
        ((__int64 (*)())off_140108038)(dst, 0, ptr);
        if (ptr2 != -1) {
            ptr2->field_8 = ptr2->field_8 - 1;
            if (!((ptr2->field_8 != 0))) {
                ptr = *(__int64 *)(ptr2 - 8);
                off_140108030();
                v9 = (__int64)dst;
                v3 = 0;
                v6 = (__int64)ptr;
                JUMPOUT(off_140108038);
            }
        }
        return v6;
    }
    return v6;
}