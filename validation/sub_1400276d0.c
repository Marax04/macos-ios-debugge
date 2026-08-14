// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3600();
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_1400276D0(struct Struct_1_t *a1) {
    __int64 v5;
    __int64 v2;
    __int64 i;
    __int64 v6;
    __int64 v9;
    __int64 v10;
    __int64 v11;
    __int64 v7;
    __int64 v8;
    __int64 result;
    __int64 v3;

    v5 = a1->field_0;
    v2 = a1->field_8;
    i = ((__int64 *)a1)[2];
    ++i;
    if (i >= v2) i = v2;
    v6 = v5 + i;
    v9 = off_14012D020;
    ((__int64 (*)())v9)(10, v5, v6);
    if ((result & 1) != 0) {
        v10 -= v5;
        v11 = v10 + 1;
        if (v10 >= v2) {
            v7 = &off_140111F70;
            sub_1400F3600(0, v11, v2, v7);
            v11 = 0;
        }
        v8 = v5 + v11;
        result = off_14012D018;
        ((__int64 (*)())result)(10, v5, v8);
        ++result;
        i -= v11;
        v3 = i;
        return v3;
    }
    return result;
}