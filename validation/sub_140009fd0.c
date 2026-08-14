// inferred from 3 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 __fastcall sub_140009FD0(struct Struct_1_t *a1) {
    __int64 result;
    __int64 v3;
    __int64 v4;
    __int64 *v2;
    __int64 v6;
    __int64 v5;

    result = a1->field_0;
    v3 = result - 1;
    if (v3 >= 4) {
        if (result == 0) JUMPOUT(0x14000a02a);
        if (result != 5) JUMPOUT(0x14000a053);
        v4 = a1->field_10;
        v2 = (__int64 *)a1;
        v6 = a1->field_18;
        if (v6 != 0) {
            v5 = v4;
            do {
                sub_140009FD0(v5);
                v5 += 32;
                --v6;
            } while ((v6 != 0));
        }
        if (*(v2 + 8) != 0) JUMPOUT(0x14000a035);
    }
    return result;
}