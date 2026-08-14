// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
extern __int64 off_140111F88;
extern __int64 off_14012D270;
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_1400F6770(__int64 *a1,struct Struct_1_t *a2, __int64 a3) {
    __int64 v3;
    __int64 v10;
    __int64 v9;
    __int64 *result;
    __int64 v2;
    __int64 *dst;
    __int64 v11;
    __int64 v6;
    __int64 v8;
    __int64 v5;
    __int64 v7;

    v3 = ((__int64 *)a2)[2];
    v10 = a2->field_8;
    if (v3 > v10) {
        v9 = &off_140111F88;
        sub_1400F3600(0, v3, v10, v9);
        result = off_14012D270;
        a1 = __readgsqword(88);
        result = a1[(__int64)result];
        result = (*(result + 128) == 0) ? 1 : 0;
        return (__int64)result;
    } else {
        v2 = a3;
        dst = a1;
        v11 = a2->field_0;
        v6 = v11 + v3;
        result = off_14012D020;
        ((__int64 (*)())result)(10, v11, v6);
        if (((__int64)result & 1) != 0) {
            a2 -= v11;
            v8 = a2 + 1;
            if (a2 >= v10) {
                v5 = &off_140111F70;
                sub_1400F3600(0, v8, v10, v5);
                v8 = 0;
            }
            v7 = v11 + v8;
            result = off_14012D018;
            ((__int64 (*)())result)(10, v11, v7);
            a2 = result + 1;
            v3 -= v8;
            sub_1400F5F40(v2, a2, v3);
            *(dst + 8) = result;
            *dst = 1;
            return v3;
        }
        return (__int64)result;
    }
}