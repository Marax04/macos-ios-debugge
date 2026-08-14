// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400416A0(struct Struct_1_t *a1, __int64 a2) {
    __int64 v_10;
    __int64 v_8;
    char *dst;
    struct Struct_2_t *result;
    __int64 *src;
    __int64 *src2;
    __int64 v5;

    *dst = -2;
    if (a1->field_0 != 0) {
        result = a1->field_8;
        if (result != 0) {
            v_10 = (__int64)result;
            src = ((__int64 *)a1)[2];
            v_8 = (__int64)src;
            src = *src;
            if (src != 0) {
                ((__int64 (*)())src)(v_10);
            }
            result = (struct Struct_2_t *)v_8;
            src2 = (__int64 *)v_10;
            if (result->field_8 != 0) {
                if (result->field_10 >= 17) {
                    src2 = *(src2 - 8);
                }
                off_140108030();
                v5 = (__int64)result;
                a2 = 0;
                JUMPOUT(off_140108038);
            }
        }
    }
    return (__int64)result;
}