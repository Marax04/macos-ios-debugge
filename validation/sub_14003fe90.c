// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_14003FAB0();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14003FE90(__int64 a1) {
    int v_10;
    char *src;
    __int64 v3;
    __int64 v9;
    __int64 v10;
    __int64 *src2;
    __int64 v8;
    __int64 result;
    struct Struct_1_t *ptr;
    __int64 v6;
    __int64 v5;
    __int64 v2;

    v3 = a1;
    v9 = off_140108030;
    v10 = off_140108038;
    a1 = src - 16;
    sub_14003FAB0(a1);
    src2 = (__int64 *)v_10;
    while (src2 != 0) {
        v8 = *src;
        result = v8 * 56;
        ptr = src2 + result;
        ptr += 360;
        if (*(src2 + result + 360) == 0) {
            if (ptr->field_20 == 0) {
                v8 <<= 5;
                src2 += v8;
                v6 = *(src2 + 8);
                ((__int64 (*)())v9)();
                ((__int64 (*)())v10)(result, 0, v6);
            }
            v5 = ptr->field_28;
            ((__int64 (*)())v9)();
            ((__int64 (*)())v10)(result, 0, v5);
            return v5;
        }
        v2 = ptr->field_8;
        ((__int64 (*)())v9)();
        ((__int64 (*)())v10)(result, 0, v2);
        return v2;
    }
    return result;
}