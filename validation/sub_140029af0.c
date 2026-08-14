// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_1400F6820();
extern __int64 off_14012D268;
extern __int64 off_140108258;

__int64 __fastcall sub_140029AF0(struct Struct_1_t *a1, int a2) {
    __int64 result;
    __int64 v2;

    if ((a2 & 1) == 0) {
        result = off_14012D268;
        result <<= 1;
        if (result != 0) {
            v2 = (__int64)a1;
            sub_1400F6820(0);
            a1 = (struct Struct_1_t *)v2;
            a1->field_1 = 1;
        }
    }
    { __int64 __xchg_tmp = a1->field_0; *(__int64 *)a1 = (__int64)(result); result = __xchg_tmp; };
    while (result == 2) {
        JUMPOUT(off_140108258);
        return (__int64)a1;
    }
    return result;
}