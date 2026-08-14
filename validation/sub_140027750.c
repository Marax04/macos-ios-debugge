// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `result`
struct Struct_2_t {
    char _pad_start[40];
    __int64 field_28; // offset 40
    char _pad_28[88];
    __int64 field_88; // offset 136
};

// inferred from 2 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3600();
__int64 sub_140027915();
extern __int64 off_140111F88;
extern __int64 off_14012D268;
extern __int64 off_14012D270;
extern __int64 off_14012D240;
extern __int64 off_14012D248;
extern __int64 off_14012D250;
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_140027750(struct Struct_1_t *a1) {
    int arg_28;
    int arg_40;
    int arg_b0;
    int v_20;
    int v_28;
    __int64 v4;
    __int64 v5;
    __int64 v13;
    struct Struct_2_t *result;
    __int64 *v9;
    struct Struct_3_t *ptr;
    __int64 v12;
    __int64 v11;
    __int64 v2;
    __int64 v6;
    __int64 v3;
    __int64 v7;
    __int64 v8;

    v4 = ((__int64 *)a1)[2];
    v5 = a1->field_8;
    if (v4 > v5) {
        v13 = &off_140111F88;
        sub_1400F3600(0, v4, v5, v13);
        arg_40 = -2;
        v_28 = (int)a1;
        v_20 = v4;
        arg_28 = v5;
        ++off_14012D268;
        if ((off_14012D268 <= 0)) JUMPOUT(0x140027dde);
        result = off_14012D270;
        v9 = __readgsqword(88);
        result = v9[(__int64)result];
        if (result->field_88 != 0) JUMPOUT(0x140027e44);
        ptr = result + 128;
        *(__int64 *)ptr = (__int64)(ptr->field_0 + 1);
        ptr->field_8 = 1;
        result = off_14012D240;
        if (result > 0x3FFFFFFD) JUMPOUT(0x140027c15);
        a1 = result + 1;
        /* cmpxchg %(__int64)a1, off_14012D240 */;
        if ((0 /* unresolved: flags != */)) JUMPOUT(0x140027c15);
        v12 = arg_b0;
        result = off_14012D248;
        if (off_14012D250 != 0) JUMPOUT(0x1400278a5);
        a1 = (struct Struct_1_t *)v_28;
        result = (struct Struct_2_t *)v_20;
        ((__int64 (*)())(result->field_28))();
        v4 = (__int64)result;
        v5 = v3;
        v11 = arg_28;
        if (v12 == 0) JUMPOUT(0x1400278f7);
        v13 = 3;
        return sub_140027915();
    } else {
        v2 = a1->field_0;
        v6 = v2 + v4;
        result = off_14012D020;
        ((__int64 (*)())result)(10, v2, v6);
        if (((__int64)result & 1) != 0) {
            v3 -= v2;
            v12 = v3 + 1;
            if (v3 >= v5) {
                v7 = &off_140111F70;
                sub_1400F3600(0, v12, v5, v7);
                v12 = 0;
            }
            v8 = v2 + v12;
            result = off_14012D018;
            ((__int64 (*)())result)(10, v2, v8);
            ++result;
            v4 -= v12;
            v3 = v4;
            return v3;
        }
        return (__int64)result;
    }
}