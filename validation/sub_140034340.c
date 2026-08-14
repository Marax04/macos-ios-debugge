// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3600();
__int64 sub_140033BC0();
__int64 sub_14002DC40();
__int64 sub_1400F27F6();
extern __int64 off_140114848;

__int64 __fastcall sub_140034340(struct Struct_1_t *a1, __int64 a2) {
    __int64 rsp;
    __int64 v_10;
    int v_8;
    __int64 *dst;
    __int64 v5;
    __int64 v3;
    __int64 v6;
    __int64 *v11;
    __int64 *result;
    __int64 v8;
    __int64 v7;
    __int64 *dst2;
    __int64 v2;
    __int64 *dst3;

    dst = rsp + 32;
    if (a2 != 0) {
        v5 = ((__int64 *)a1)[2];
        v3 = v5;
        v3 -= a2;
        if ((v3 < 0)) {
            v6 = &off_140114848;
            sub_1400F3600(0, a2, v5, v6);
            dst = rsp + 48;
            *dst = -2;
            v11 = (__int64 *)a1;
            result = a1->field_0;
            v8 = *result;
            sub_140033BC0(v8);
            if (result != 0) {
                v_10 = (__int64)result;
                v7 = v11 + 8;
                v_8 = v7;
                if (*(v11 + 8) != 0) {
                    sub_14002DC40(v_8);
                }
                result = (__int64 *)v_10;
                dst2 = (__int64 *)v_8;
                *dst2 = result;
            }
            result = (result != 0) ? 1 : 0;
            return (__int64)result;
        } else {
            ((__int64 *)a1)[2] = (__int64)(0);
            if (!((0 /* unresolved: flags == */))) {
                v2 = a1->field_8;
                a2 += v2;
                dst3 = (__int64 *)a1;
                sub_1400F27F6(v2, a2, v3);
                *(dst3 + 16) = v3;
            }
        }
    }
    return (__int64)result;
}