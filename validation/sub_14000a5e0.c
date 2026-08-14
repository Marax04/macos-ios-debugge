// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14000A5E0(__int64 *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 *src;
    __int64 result;
    __int64 *src2;
    struct Struct_2_t *ptr2;
    __int64 v6;

    ptr = (struct Struct_1_t *)a1;
    v5 = *a1;
    if (v5 == 1) {
        src = ptr->field_8;
        result = (__int64)src;
        result &= 3;
        if (result == 1) {
            do {
                src2 = *(src - 1);
                ptr2 = *(src + 7);
                v5 = ptr2->field_0;
                --src;
                if (ptr2->field_8 == 0) {
                    off_140108030();
                    ((__int64 (*)())off_140108038)(v5, 0, src);
                    off_140108030();
                    v6 = v5;
                    JUMPOUT(off_140108038);
                }
                if (ptr2->field_10 < 17) {
                    off_140108030();
                    ((__int64 (*)())off_140108038)(v5, 0, src2);
                    return v6;
                }
                src2 = *(src2 - 8);
                return (__int64)src2;
            } while (true);
        }
        return (__int64)src2;
    } else {
        if (v5 == 0) {
            if (ptr->field_10 != 0) {
                src = ptr->field_8;
                return (__int64)src;
            }
        }
        return (__int64)src;
    }
    return result;
}