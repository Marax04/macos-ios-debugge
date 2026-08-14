// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char field_0; // offset 0
    char field_1; // offset 1
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14000FD8A();
__int64 sub_14000FD40();

__int64 __fastcall sub_14000FC90(size_t *a1, size_t *a2, __int64 a3) {
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 *src;
    int v1;
    struct Struct_2_t *ptr2;
    __int64 v8;
    __int64 v10;
    __int64 v5;
    __int64 v9;

    v3 = a3;
    ptr = (struct Struct_1_t *)a2;
    src = (__int64 *)a1;
    if (a3 == 0) {
        v3 += (__int64)ptr;
        v1 = v_48;
        v_38 = v1;
        v_30 = v_40;
        ptr2 = *src;
        v8 = ptr2->field_0;
        v10 = ptr2->field_8;
        a2 = 0;
        return sub_14000FD8A();
    } else {
        a1 = ptr->field_0;
        a2 = a1;
        if (a2 < 0) {
            v1 = (int)a2;
            v1 &= 31;
            a3 = ptr->field_1;
            a3 &= 63;
            if (a2 <= 223) JUMPOUT(0x14000fd29);
            a2 = ptr->field_2;
            a3 <<= 6;
            a2 = (size_t *)((__int64)(__int64)a2 & 63);
            a2 = (size_t *)((__int64)(__int64)a2 | a3);
            if (a1 < 240) JUMPOUT(0x14000fd37);
            v5 = ptr + 4;
            a1 = ptr->field_3;
            v1 &= 7;
            v1 <<= 18;
            a2 = (size_t *)((__int64)(__int64)a2 << 6);
            a1 = (size_t *)((__int64)(__int64)a1 & 63);
            a1 = (size_t *)((__int64)(__int64)a1 | (__int64)a2);
            a1 = (size_t *)((__int64)(__int64)a1 | v1);
            a2 = a1;
            return sub_14000FD40();
        } else {
            v9 = ptr + 1;
            return sub_14000FD40();
        }
    }
}