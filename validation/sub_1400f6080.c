// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 __fastcall sub_1400F6080(struct Struct_1_t *a1, __int64 a2, __int64 *a3, size_t a4) {
    __int64 result;

    result = a1->field_8;
    a2 = ((__int64 *)a1)[2];
    if (a2 < result) {
        a3 = a1->field_0;
        result = -result;
        ++a2;
        a4 = *(a3 + a2 - 1);
        while (a4 != 34) {
            if (a4 != 92) {
                if (a4 >= 32) {
                    ((__int64 *)a1)[2] = (__int64)(a2);
                    a4 = result + a2;
                    ++a4;
                    ++a2;
                }
            }
        }
    }
    return result;
}