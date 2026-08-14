// inferred from 3 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140063066();

void __fastcall sub_140063020(__int64 a1,struct Struct_1_t *a2) {
    __int64 v1;
    __int64 v2;
    __int64 v3;

    v1 = a2->field_10;
    v2 = a2->field_18;
    v3 = v1;
    v3 -= a2->field_0;
    sub_140063066();
}