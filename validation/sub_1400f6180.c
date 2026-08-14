// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
extern __int64 off_140111F88;
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_1400F6180(struct Struct_1_t *a1,struct Struct_2_t *a2, __int64 a3) {
    __int64 v3;
    __int64 v9;
    __int64 v5;
    __int64 v2;
    __int64 *dst;
    __int64 v6;
    __int64 result;
    __int64 v10;
    __int64 v7;
    __int64 v8;

    v3 = ((__int64 *)a2)[2];
    v9 = a2->field_8;
    if (v3 > v9) {
        v5 = &off_140111F88;
        sub_1400F3600(0, v3, v9, v5);
        v3 = ((__int64 *)a1)[2];
        v2 = a1->field_8;
        if (v3 > v2) JUMPOUT(0x1400f62b6);
        dst = (__int64 *)a2;
        v6 = a1->field_0;
        a3 = v6 + v3;
        result = off_14012D020;
        ((__int64 (*)())result)(10, v6, a3);
        if ((result & 1) != 0) {
            a2 -= v6;
            v10 = a2 + 1;
            if (a2 >= v2) {
                v5 = &off_140111F70;
                sub_1400F3600(0, v10, v2, v5);
                v10 = 0;
            }
            a3 = v6 + v10;
            result = off_14012D018;
            ((__int64 (*)())result)(10, v6, a3);
            a2 = result + 1;
            v3 -= v10;
            a1 = (struct Struct_1_t *)dst;
            a3 = v3;
            return sub_1400F5F40();
        }
        return a3;
    } else {
        v2 = a3;
        dst = (__int64 *)a1;
        v7 = a2->field_0;
        a3 = v7 + v3;
        result = off_14012D020;
        ((__int64 (*)())result)(10, v7, a3);
        if ((result & 1) != 0) {
            a2 -= v7;
            v8 = a2 + 1;
            if (a2 >= v9) {
                v5 = &off_140111F70;
                sub_1400F3600(0, v8, v9, v5);
                v8 = 0;
            }
            a3 = v7 + v8;
            result = off_14012D018;
            ((__int64 (*)())result)(10, v7, a3);
            a2 = result + 1;
            v3 -= v8;
            sub_1400F5F40(v2, a2, v3);
            *(dst + 8) = result;
            *dst = 1;
            return v3;
        }
        return result;
    }
}