// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_140053A40();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140053350(struct Struct_1_t *a1) {
    __int64 *v5;
    __int64 v4;
    __int64 v3;
    __int64 v2;
    __int64 v1;

    v5 = (__int64 *)a1;
    v4 = a1->field_20;
    v3 = a1->field_28;
    sub_140053A40(v4, v3);
    if (*(v5 + 24) != 0) {
        off_140108030();
        v2 = v1;
        v3 = 0;
        JUMPOUT(off_140108038);
    }
    return v3;
}