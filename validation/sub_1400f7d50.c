// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[168];
    __int64 field_A8; // offset 168
    char _pad_A8[168];
    __int64 field_158; // offset 344
    __int64 field_160; // offset 352
    __int64 field_168; // offset 360
    __int64 field_170; // offset 368
};

__int64 sub_1400F7BC0();
__int64 sub_140046040();
__int64 sub_140046190();
__int64 sub_1400462A0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140114FA8;

__int64 __fastcall sub_1400F7D50(__int64 a1, __int64 a2) {
    char *str;
    char *str2;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v2;
    __int64 result;
    __int64 v4;
    __int64 v6;
    __int64 v7;

    ptr = (struct Struct_1_t *)v7;
    str2 = 11;
    v5 = &off_140114FA8;
    sub_1400F7BC0(a1, str2, str, v5);
    v2 = ptr->field_160;
    result = ptr->field_170;
    result -= v2;
    result >>= 3;
    a2 = 0x8F9C18F9C18F9C19;
    a2 *= result;
    sub_140046040(v2, a2);
    if (ptr->field_168 != 0) {
        v4 = ptr->field_158;
        off_140108030();
        off_140108038(result, 0, v4);
    }
    if (ptr->field_A8 != 12) {
        v6 = ptr + 168;
        ptr += 24;
        sub_140046190(ptr);
        sub_1400462A0(v6);
    }
    return result;
}