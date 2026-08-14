// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_1400F6820();
extern __int64 off_14012D268;
extern __int64 off_140108258;

__int64 __fastcall sub_140040970(__int64 *a1) {
    struct Struct_1_t *ptr;
    __int64 result;

    ptr = *(a1 + 8);
    result = a1[2];
    if (result == 0) {
        result = off_14012D268;
        result <<= 1;
        if (result != 0) {
            sub_1400F6820(ptr);
            ptr->field_1 = 1;
        }
    }
    result = 0;
    { __int64 __xchg_tmp = ptr->field_0; *(__int64 *)ptr = (__int64)(result); result = __xchg_tmp; };
    while (result == 2) {
        JUMPOUT(off_140108258);
        return result;
    }
    return result;
}