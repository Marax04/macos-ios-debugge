// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400F7BC0();
__int64 sub_140045D80();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140114FA8;

__int64 __fastcall sub_1400F7DF0(__int64 a1, __int64 a2) {
    char *str;
    char *str2;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v2;
    __int64 result;
    __int64 v4;

    ptr = (struct Struct_1_t *)v4;
    str2 = 10;
    v5 = &off_140114FA8;
    sub_1400F7BC0(a1, str2, str, v5);
    v2 = ptr->field_8;
    result = ptr->field_18;
    result -= v2;
    result >>= 4;
    a2 = 0x2E8BA2E8BA2E8BA3;
    a2 *= result;
    sub_140045D80(v2, a2);
    if (ptr->field_10 != 0) {
        ptr = ptr->field_0;
        off_140108030();
        off_140108038(result, 0, ptr);
    }
    return result;
}