// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
};

__int64 sub_1400A3AD5();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400A39F0(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 v9;
    __int64 v10;
    __int64 v7;
    __int64 v8;
    __int64 v5;
    __int64 v2;
    __int64 v6;
    __int64 v1;

    ptr = (struct Struct_1_t *)a1;
    v3 = *(a1 + 8);
    v9 = a1[2];
    if (v9 != 0) {
        v10 = v3 + 16;
        v7 = off_140108030;
        v8 = off_140108038;
        do {
            v10 += 32;
            --v9;
        } while (!((v9 == 0)));
    }
    if (ptr->field_0 != 0) {
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(v1, 0, v3);
    }
    if (ptr->field_18 != 0) {
        v3 = ptr->field_20;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(v1, 0, v3);
    }
    v3 = ptr->field_30;
    if (v3 == 0) JUMPOUT(0x1400a3c96);
    v5 = ptr->field_38;
    v2 = ptr->field_40;
    if (v2 == 0) JUMPOUT(0x1400a3ca6);
    ptr = 0;
    v9 = off_140108030;
    v10 = off_140108038;
    v6 = v3;
    return sub_1400A3AD5();
}