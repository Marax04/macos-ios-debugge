// inferred from 3 accesses on `a1`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_1400F5D40(struct Struct_1_t *a1, __int64 a2) {
    __int64 v3;
    __int64 v2;
    __int64 v11;
    __int64 i;
    __int64 v5;
    __int64 v9;
    __int64 v12;
    __int64 v6;
    __int64 v7;
    __int64 v10;
    __int64 v8;
    int v1;

    v3 = a2;
    v2 = a1->field_18;
    v11 = a1->field_20;
    i = a1->field_28;
    ++i;
    if (i >= v11) i = v11;
    v5 = v2 + i;
    v9 = off_14012D020;
    ((__int64 (*)())v9)(10, v2, v5);
    if ((v1 & 1) != 0) {
        a2 -= v2;
        v12 = a2 + 1;
        if (a2 >= v11) {
            v6 = &off_140111F70;
            sub_1400F3600(0, v12, v11, v6);
            v12 = 0;
        }
        v7 = v2 + v12;
        v10 = off_14012D018;
        ((__int64 (*)())v10)(10, v2, v7);
        a2 = v10 + 1;
        i -= v12;
        a1 = (struct Struct_1_t *)v3;
        v8 = i;
        return sub_1400F5F40();
    }
    return v8;
}