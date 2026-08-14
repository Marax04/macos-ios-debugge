// inferred from 6 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
};

extern __int64 off_140108038;
extern __int64 off_140108030;

__int64 __fastcall sub_140073860(__int64 *a1, __int64 a2) {
    __int64 result;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v5;
    __int64 v2;
    __int64 *src2;
    __int64 v11;
    __int64 v8;
    __int64 *src3;
    __int64 v6;
    __int64 v7;

    result = *a1;
    if (result != 0) {
        ptr = (struct Struct_1_t *)a1;
        if (result != 1) {
            src = ptr->field_8;
            ptr = ptr->field_10;
            result = ptr->field_0;
            if (result != 0) {
                ((__int64 (*)())result)(src);
            }
            if (ptr->field_8 != 0) {
                if (ptr->field_10 >= 17) {
                    src = *(src - 8);
                }
                ((__int64 (*)())off_140108030)();
                a1 = (__int64 *)result;
                a2 = 0;
                v5 = (__int64)src;
                JUMPOUT(off_140108038);
            }
        } else {
            v2 = ptr->field_18;
            if (v2 != 0) {
                src2 = ptr->field_8;
                src2 += 56;
                v11 = off_140108030;
                v8 = off_140108038;
                do {
                    result = *(src2 - 56);
                    result = -result;
                    src2 += 88;
                    --v2;
                } while (!((v2 == 0)));
            }
            src = ptr->field_30;
            if (src != 0) {
                src3 = ptr->field_20;
                src3 += 56;
                v6 = off_140108030;
                v7 = off_140108038;
                do {
                    result = *(src3 - 56);
                    result = -result;
                    src3 += 88;
                    --src;
                } while (!((src == 0)));
            }
        }
    }
    return result;
}