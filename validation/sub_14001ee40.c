// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
    char _pad_28[8];
    __int64 field_38; // offset 56
};

__int64 sub_14001EEB9();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14001EE40(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v2;
    __int64 *dst;
    __int64 v6;
    __int64 v7;
    __int64 v5;

    ptr = (struct Struct_1_t *)a1;
    src = *(a1 + 8);
    v2 = a1[3];
    v2 -= (__int64)src;
    if (!((v2 == 0))) {
        v2 >>= 5;
        do {
            dst = *src;
            *dst = *dst - 1;
            src += 32;
            --v2;
        } while (!((v2 == 0)));
    }
    if (ptr->field_10 != 0) {
        v6 = ptr->field_0;
        off_140108030();
        off_140108038(dst, 0);
    }
    v7 = ptr->field_28;
    v5 = ptr->field_38;
    v5 -= v7;
    if ((v5 == 0)) JUMPOUT(0x14001eecc);
    v5 >>= 4;
    return sub_14001EEB9();
}