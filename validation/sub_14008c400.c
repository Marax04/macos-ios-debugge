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

__int64 __fastcall sub_14008C400(__int64 *a1, __int64 a2) {
    __int64 result;
    struct Struct_1_t *ptr;
    __int64 *src;
    __int64 v5;
    __int64 v2;
    __int64 v10;
    __int64 v11;
    __int64 v8;
    __int64 v9;
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
                v10 = ptr->field_8;
                v10 += 24;
                v11 = off_140108030;
                v8 = off_140108038;
                do {
                    v10 += 40;
                    --v2;
                } while (!((v2 == 0)));
            }
            src = ptr->field_30;
            if (src != 0) {
                v9 = ptr->field_20;
                v9 += 24;
                v6 = off_140108030;
                v7 = off_140108038;
                do {
                    v9 += 40;
                    --src;
                } while (!((src == 0)));
            }
        }
    }
    return result;
}