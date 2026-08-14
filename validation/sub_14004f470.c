// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 5 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14004F470(struct Struct_1_t *a1, __int64 a2) {
    __int64 result;
    struct Struct_2_t *ptr;
    __int64 v3;
    __int64 *src;
    __int64 v2;
    __int64 v5;

    result = a1->field_0;
    if (result != 0) {
        ptr = (struct Struct_2_t *)a1;
        if (a1->field_8 != 0) {
            v3 = ptr->field_10;
            off_140108030();
            ((__int64 (*)())off_140108038)(result, 0, v3);
        }
        src = ptr->field_20;
        if (src != 0) {
            ptr = ptr->field_28;
            result = ptr->field_0;
            if (result != 0) {
                ((__int64 (*)())result)(src);
            }
            if (ptr->field_8 != 0) {
                if (ptr->field_10 >= 17) {
                    src = *(src - 8);
                }
                off_140108030();
                v2 = result;
                a2 = 0;
                v5 = (__int64)src;
                JUMPOUT(off_140108038);
            }
        }
    }
    return result;
}