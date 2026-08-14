// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[8];
    char field_18; // offset 24
    int field_19; // offset 25
    __int16 field_1D; // offset 29
    char field_1F; // offset 31
    __int64 field_20; // offset 32
};

__int64 sub_140052E40();
__int64 sub_140052A21();
extern __int64 off_140115748;

__int64 __fastcall sub_140051EE0(int a1, __int64 a2, __int64 a3) {
    int v_30;
    int v_48;
    char *str;
    char *str2;
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v6;
    __int64 v4;
    __int64 v7;
    __int64 v8;
    int v1;

    v2 = a2;
    ptr = (struct Struct_1_t *)a1;
    str2 = (char *)a2;
    v_48 = a3;
    sub_140052E40(str, str2);
    if (v_30 != 9) {
        v5 = v_30;
        if (v1 == 0) JUMPOUT(0x140051f7d);
        ptr->field_8 = 0;
        v6 = &off_140115748;
        ptr->field_18 = v6;
        ptr->field_20 = 12;
        return sub_140052A21();
    } else {
        v4 = &off_140115748;
        v7 = v4;
        v7 >>= 8;
        ptr->field_8 = 0;
        ptr->field_18 = v1;
        v8 = v4;
        v8 >>= 56;
        ptr->field_1F = a2;
        v4 >>= 40;
        ptr->field_1D = v1;
        ptr->field_19 = a1;
        ptr->field_20 = 12;
        return sub_140052A21();
    }
}