// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14002F772();

__int64 __fastcall sub_14002F640(__int64 a1,struct Struct_1_t *a2, __int64 a3) {
    char *dst;
    int v6;
    __int64 *src;
    __int64 v2;
    __int64 v3;
    int v5;
    __int64 v1;

    *dst = -2;
    v6 = ((__int64 *)a2)[2];
    if (v6 == 0) {
        src = a2->field_0;
        v2 = a2->field_8;
        if (src == v2) JUMPOUT(0x14002f6a4);
        v3 = src + 1;
        *(__int64 *)a2 = (__int64)(v3);
        v5 = *src;
        v6 = v5;
        if (v6 < 0) JUMPOUT(0x14002f6c0);
        a3 = 0;
        return sub_14002F772();
    } else {
        ((__int64 *)a2)[2] = (__int64)(0);
        a1 = a2->field_0;
        v1 = a2->field_8;
        a3 = 0;
        return sub_14002F772();
    }
}