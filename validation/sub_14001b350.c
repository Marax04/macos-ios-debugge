// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

extern __int64 off_1401133CD;
extern __int64 off_14010FF11;

__int64 __fastcall sub_14001B350(__int64 *a1,struct Struct_1_t *a2, __int64 a3, __int64 a4) {
    __int64 *result;
    __int64 v5;
    __int64 v2;
    int v3;
    __int64 v4;
    __int64 v6;

    a3 = a2->field_8;
    if (a3 == 0) {
        *a1 = 0;
    } else {
        result = a2->field_0;
        a4 = 0;
        v5 = &off_1401133CD;
        v2 = &off_14010FF11;
        do {
            v3 = *(result + a4);
            v4 = a4 + 1;
            a4 = v4;
        } while (v4 < a3);
        v6 = result + v4;
        a3 -= v4;
        *(__int64 *)a2 = (__int64)(v6);
        a2->field_8 = a3;
        v4 -= a4;
        *a1 = result;
        result += a4;
        *(a1 + 8) = a4;
        a1[2] = result;
        a1[3] = v4;
    }
    return (__int64)result;
}