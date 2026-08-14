// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14002EAD3();

void __fastcall sub_14002EA90(__int64 a1,struct Struct_1_t *a2) {
    int v2;
    __int64 v1;
    __int64 v3;
    __int64 v4;

    v2 = ((__int64 *)a2)[2];
    v1 = a2->field_0;
    v3 = a2->field_8;
    v4 = -1;
    sub_14002EAD3();
}