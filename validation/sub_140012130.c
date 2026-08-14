// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 __fastcall sub_140012130(__int64 a1, int a2, int a3, __int64 a4) {
    int arg_50;
    __int64 v3;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v5;
    __int64 result;

    v3 = a4;
    ptr = (struct Struct_1_t *)a2;
    v4 = arg_50;
    if (a3 != 0x110000) {
        v5 = a1;
        a2 = a3;
        ((__int64 (*)())(ptr->field_20))();
        a2 = result;
        result = 1;
        if (a2 == 0) {
            if (v3 != 0) {
                result = ptr->field_18;
                a2 = v3;
                JUMPOUT(result);
            }
            result = 0;
        }
        return result;
    }
    return result;
}