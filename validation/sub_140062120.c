// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F27F0();

__int64 __fastcall sub_140062120(struct Struct_1_t *a1) {
    __int64 v3;
    __int64 *dst;
    __int64 v4;
    __int64 v2;
    __int64 result;
    __int64 v5;

    if (__OFSUB(v5, a1->field_0)) {
        v3 = ((__int64 *)a1)[2];
        if (v3 < 0) {
            sub_1400F3360(0);
        }
        dst = (__int64 *)a1;
        v4 = a1->field_8;
        if (!((0 /* unresolved: flags == */))) {
            sub_14002EDF0(0, v3);
            v2 = v5;
            if (v5 == 0) {
                sub_1400F3326(1, v3);
                v2 = 1;
            }
            sub_1400F27F0(v2, v4);
            a1 = (struct Struct_1_t *)dst;
            *dst = v3;
            *(dst + 8) = v2;
            result = (__int64)a1;
            return result;
        }
        return result;
    }
    return result;
}