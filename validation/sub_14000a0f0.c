// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[24];
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

// inferred from 4 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    char _pad_20[96];
    __int64 field_88; // offset 136
    __int64 field_90; // offset 144
    __int64 field_98; // offset 152
};

__int64 sub_14000A1E3();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14000A0F0(__int64 *a1, __int64 a2) {
    __int64 v_28;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v8;
    struct Struct_2_t *ptr2;
    __int64 v7;
    __int64 v6;
    __int64 v5;
    __int64 v2;
    __int64 v1;

    ptr = (struct Struct_1_t *)a1;
    if (*a1 != 0) {
        v4 = ptr->field_8;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(v1, 0, v4);
    }
    v4 = ptr->field_28;
    v_28 = (__int64)ptr;
    ptr = ptr->field_30;
    if (ptr != 0) {
        v8 = v4 + 16;
        ptr2 = off_140108030;
        v7 = off_140108038;
        do {
            v8 += 40;
            --ptr;
        } while (!((ptr == 0)));
    }
    ptr2 = (struct Struct_2_t *)v_28;
    if (ptr2->field_20 != 0) {
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(v1, 0, v4);
    }
    v4 = ptr2->field_88;
    if (v4 == 0) JUMPOUT(0x14000a50d);
    ptr = ptr2->field_90;
    v6 = ptr2->field_98;
    if (v6 == 0) JUMPOUT(0x14000a432);
    ptr2 = off_140108030;
    v5 = off_140108038;
    v2 = v4;
    v4 = 0;
    return sub_14000A1E3();
}