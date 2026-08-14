// inferred from 3 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

int __fastcall sub_14000A690(struct Struct_1_t *a1) {
    int result;
    __int64 v3;
    __int64 *v2;
    __int64 v5;
    __int64 v4;

    result = a1->field_0;
    if (result >= 3) {
        if ((0 /* unresolved: flags == */)) JUMPOUT(0x14000a6fa);
        if (result != 4) JUMPOUT(0x14000a72d);
        v3 = a1->field_10;
        v2 = (__int64 *)a1;
        v5 = a1->field_18;
        if (v5 != 0) {
            v4 = v3;
            do {
                sub_14000A690(v4);
                v4 += 32;
                --v5;
            } while ((v5 != 0));
        }
        if (*(v2 + 8) != 0) JUMPOUT(0x14000a705);
    }
    return result;
}