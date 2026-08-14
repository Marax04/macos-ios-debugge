// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[168];
    __int64 field_A8; // offset 168
    char _pad_A8[168];
    __int64 field_158; // offset 344
    char _pad_158[8];
    __int64 field_168; // offset 360
    __int64 field_170; // offset 368
};

__int64 sub_140046040();
__int64 sub_140046190();
__int64 sub_1400462A0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14004F360(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v1;
    __int64 v6;
    __int64 v3;
    __int64 v5;
    __int64 v4;

    ptr = (struct Struct_1_t *)a1;
    a1 = a1[44];
    v1 = ptr->field_170;
    v1 -= (__int64)a1;
    v1 >>= 3;
    v6 = 0x8F9C18F9C18F9C19;
    v6 *= v1;
    sub_140046040(a1, v6);
    if (ptr->field_168 != 0) {
        v3 = ptr->field_158;
        off_140108030();
        off_140108038(v1, 0);
    }
    if (ptr->field_A8 != 12) {
        v5 = ptr + 168;
        ptr += 24;
        sub_140046190(ptr);
        v4 = v5;
        return sub_1400462A0();
    } else {
        return v4;
    }
}