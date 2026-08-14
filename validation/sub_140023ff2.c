// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 __fastcall sub_140023FF2(int *a1, int a2) {
    int v3;
    int v4;
    struct Struct_1_t *ptr;
    __int64 *result;

    if (a1 == 0) {
        v3 = 0;
    } else {
        v4 = a2;
        ptr = (struct Struct_1_t *)a1;
        a1 = *a1;
        result = ptr->field_8;
        a2 = 39;
        ((__int64 (*)())(*(result + 32)))();
        v3 = 1;
        if (result == 0) {
            do {
                a1 = ptr->field_0;
                result = ptr->field_8;
                ((__int64 (*)())(*(result + 32)))();
                v4 = 0x110000;
            } while (result == 0);
        }
    }
    result = (__int64 *)v3;
    return (__int64)result;
}