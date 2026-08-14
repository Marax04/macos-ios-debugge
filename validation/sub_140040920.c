// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

extern __int64 off_140108048;

void __fastcall sub_140040920(__int64 *a1) {
    struct Struct_1_t *ptr;
    __int64 v1;
    __int64 v3;
    __int64 v4;

    ptr = a1;
    if (*a1 != 0) {
        v1 = ptr->field_8;
        ((__int64 (*)())off_140108048)(v1);
    }
    if (ptr->field_10 != 0) {
        v3 = ptr->field_18;
        ((__int64 (*)())off_140108048)(v3);
    }
    if (ptr->field_20 != 0) {
        v4 = ptr->field_28;
        JUMPOUT(off_140108048);
    }
    return;
}