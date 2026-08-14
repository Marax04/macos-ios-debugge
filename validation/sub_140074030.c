// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

extern __int64 off_140108038;
extern __int64 off_140108030;

__int64 __fastcall sub_140074030(struct Struct_1_t *a1, __int64 a2) {
    __int64 result;
    __int64 *src;
    struct Struct_2_t *ptr;
    __int64 v6;
    __int64 v5;
    __int64 v4;
    __int64 *src2;
    __int64 v8;
    __int64 v9;

    result = a1->field_0;
    if (result != 0) {
        if (result != 1) {
            src = a1->field_8;
            ptr = ((__int64 *)a1)[2];
            result = ptr->field_0;
            if (result != 0) {
                ((__int64 (*)())result)(src);
            }
            if (ptr->field_8 != 0) {
                if (ptr->field_10 >= 17) {
                    src = *(src - 8);
                }
                ((__int64 (*)())off_140108030)();
                v6 = result;
                a2 = 0;
                v5 = (__int64)src;
                JUMPOUT(off_140108038);
            }
        } else {
            v4 = ((__int64 *)a1)[3];
            if (v4 != 0) {
                src2 = a1->field_8;
                src2 += 56;
                v8 = off_140108030;
                v9 = off_140108038;
                do {
                    result = *(src2 - 56);
                    result = -result;
                    src2 += 88;
                    --v4;
                } while (!((v4 == 0)));
            }
        }
    }
    return result;
}