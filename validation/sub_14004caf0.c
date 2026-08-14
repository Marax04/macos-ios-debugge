// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14004CAF0(struct Struct_1_t *a1, __int64 a2) {
    __int64 v6;
    __int64 v4;
    __int64 v3;
    __int64 v2;
    __int64 result;
    __int64 v8;
    __int64 v7;
    __int64 v5;

    v6 = a1->field_0;
    v4 = 0x8000000000000003;
    if (v6 != v4) {
        if (v6 > 0) {
            v3 = a1->field_8;
            v2 = (__int64)a1;
            off_140108030();
            ((__int64 (*)())off_140108038)(v6, 0, v3);
        }
    }
    result = ((__int64 *)a1)[3];
    if (result != v4) {
        if (result > 0) {
            v8 = ((__int64 *)a1)[4];
            off_140108030(v2);
            v7 = result;
            a2 = 0;
            v5 = v8;
            JUMPOUT(off_140108038);
        }
    }
    return result;
}