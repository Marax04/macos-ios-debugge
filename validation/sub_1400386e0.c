// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400387E3();
__int64 sub_140038835();

__int64 __fastcall sub_1400386E0(__int64 a1,struct Struct_1_t *a2) {
    char *dst;
    __int64 v2;
    __int64 v1;
    __int64 *v3;
    __int64 v4;

    *dst = -2;
    v2 = a2->field_0;
    v1 = v2;
    v1 = -v1;
    if ((0 /* overflow check on (-v1) */)) {
        v3 = a2->field_8;
        v4 = ((__int64 *)a2)[2];
        if (v4 > 15) JUMPOUT(0x140038748);
        if (v4 == 0) JUMPOUT(0x1400387e3);
        a1 = 0;
        do {
            if (*(v3 + a1) == 0) JUMPOUT(0x1400388c5);
            ++a1;
        } while (v4 != a1);
        return sub_1400387E3();
    } else {
        v3 = 0;
        return sub_140038835();
    }
}