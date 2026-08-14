// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140009C30();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140009BA0(struct Struct_1_t *a1) {
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    __int64 v2;
    __int64 v1;
    __int64 v3;
    __int64 v5;
    __int64 v4;

    v2 = a1->field_0;
    if (v2 == 0) {
        a1 = 0;
        v1 = 0;
    } else {
        v3 = a1->field_8;
        v1 = ((__int64 *)a1)[2];
        v_28 = 0;
        v_30 = v2;
        v_38 = v3;
        v_48 = 0;
        v_50 = v2;
        v_58 = v3;
        a1 = 1;
    }
    v_20 = (int)a1;
    v_40 = (int)a1;
    v_60 = v1;
    v5 = off_140108030;
    v4 = off_140108038;
    return sub_140009C30();
}