// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

__int64 sub_1400C76FB();

__int64 __fastcall sub_1400C7A5D() {
    int v_28;
    __int64 v4;
    __int64 v1;
    __int64 v2;
    struct Struct_1_t *ptr;

    v4 = v_28;
    v1 = ptr->field_0;
    v2 = ptr->field_10;
    return sub_1400C76FB();
}