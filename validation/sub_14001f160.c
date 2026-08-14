// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[512];
    __int64 field_200; // offset 512
    __int64 field_208; // offset 520
};

// inferred from 8 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[128];
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
    char _pad_88[112];
    __int64 field_100; // offset 256
    char _pad_100[136];
    __int64 field_190; // offset 400
    __int64 field_198; // offset 408
    char _pad_198[56];
    __int64 field_1D8; // offset 472
    __int64 field_1E0; // offset 480
    char _pad_1E0[16];
    __int64 field_1F8; // offset 504
};

__int64 sub_14001F259();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14001F160(struct Struct_1_t *a1, __int64 a2) {
    struct Struct_2_t *ptr;
    __int64 v4;
    __int64 v9;
    __int64 *src;
    __int64 *dst;
    __int64 v7;
    __int64 v5;
    __int64 v6;
    __int64 v8;

    ptr = (struct Struct_2_t *)a1;
    v4 = a1->field_200;
    v9 = a1->field_208;
    if (v9 != 0) {
        src = v4 + 24;
        do {
            dst = *src;
            *dst = *dst - 1;
            src += 40;
            --v9;
        } while (!((v9 == 0)));
    }
    if (ptr->field_1F8 != 0) {
        off_140108030();
        off_140108038(dst, 0, v4);
    }
    if (ptr->field_1D8 != 0) {
        dst = ptr->field_1E0;
        v4 = *(dst - 8);
        off_140108030();
        off_140108038(dst, 0, v4);
    }
    v7 = ptr->field_100;
    v5 = ptr->field_80;
    v4 = ptr->field_88;
    v5 &= -2;
    v7 &= -2;
    if (v5 != v7) JUMPOUT(0x14001f3a2);
    off_140108030();
    off_140108038(dst, 0, v4);
    v4 = ptr->field_190;
    v6 = ptr->field_198;
    if (v6 == 0) JUMPOUT(0x14001f26c);
    v8 = v4;
    return sub_14001F259();
}