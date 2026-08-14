// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140044E90(struct Struct_1_t *a1, __int64 a2) {
    __int64 result;
    __int64 v3;
    __int64 *v4;
    __int64 v6;
    __int64 v2;
    __int64 v5;

    result = ((__int64 *)a1)[4];
    result <<= 1;
    if (result != 0) {
        v3 = ((__int64 *)a1)[5];
        v4 = (__int64 *)a1;
        off_140108030();
        ((__int64 (*)())off_140108038)(result, 0, v3);
        if (*v4 != 2) {
            if (a1->field_8 != 0) {
                v6 = ((__int64 *)a1)[2];
                off_140108030(v4);
                v2 = result;
                a2 = 0;
                v5 = v6;
                JUMPOUT(off_140108038);
            }
        }
    } else {
        if (a1->field_0 != 2) {
            return v5;
        } else {
        }
    }
    return result;
}