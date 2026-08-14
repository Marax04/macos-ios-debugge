// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140037030(__int64 a1, __int64 *a2) {
    int v_10;
    int v_8;
    char *dst;
    __int64 v2;
    __int64 *src;
    struct Struct_1_t *result;
    __int64 v5;

    *dst = -2;
    v_10 = a1;
    v_8 = (int)a2;
    v2 = *a2;
    if (v2 != 0) {
        ((__int64 (*)())v2)(v_10);
    }
    src = (__int64 *)v_10;
    result = (struct Struct_1_t *)v_8;
    if (result->field_8 != 0) {
        if (result->field_10 >= 17) {
            src = *(src - 8);
        }
        off_140108030();
        v5 = (__int64)result;
        a2 = 0;
        JUMPOUT(off_140108038);
    }
    return (__int64)result;
}