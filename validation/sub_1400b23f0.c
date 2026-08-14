// inferred from 3 accesses on `a1`
struct Struct_1_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

__int64 __fastcall sub_1400B23F0(struct Struct_1_t *a1, int a2, int a3, int *a4) {
    __int64 result;
    __int64 v5;
    __int64 v2;
    __int64 v3;
    __int64 v4;

    result = a1->field_8;
    a3 = ((__int64 *)a1)[1];
    a4 = 0;
    a4 = (a3 < a1->field_4) ? 1 : 0;
    v5 = 0;
    v5 = (result < a1->field_0) ? 1 : 0;
    if (result == a1->field_0) v5 = a4;
    if (v5 != 0) {
        a4 = a1->field_0;
        a1->field_8 = a4;
        a3 <<= 32;
        a3 |= result;
        *(__int64 *)a1 = (__int64)(a3);
    }
    if (a2 != 2) {
        result = ((__int64 *)a1)[2];
        a3 = ((__int64 *)a1)[2];
        a4 = 0;
        a4 = (a3 < ((__int64 *)a1)[1]) ? 1 : 0;
        v5 = 0;
        v5 = (result < a1->field_8) ? 1 : 0;
        if (result == a1->field_8) v5 = a4;
        if (v5 == 1) {
            a4 = a1->field_8;
            ((__int64 *)a1)[2] = (__int64)(a4);
            a4 = 0;
            a4 = (a3 < a1->field_4) ? 1 : 0;
            v5 = 0;
            v5 = (result < a1->field_0) ? 1 : 0;
            if (result == a1->field_0) v5 = a4;
            if (v5 != 1) {
                a4 = a1 + 8;
            } else {
                a4 = a1->field_0;
                a1->field_8 = a4;
                a4 = (int *)a1;
            }
            a3 <<= 32;
            a3 |= result;
            *a4 = a3;
        }
        if (a2 != 3) {
            result = ((__int64 *)a1)[3];
            a3 = ((__int64 *)a1)[3];
            a4 = 0;
            a4 = (a3 < ((__int64 *)a1)[2]) ? 1 : 0;
            v5 = 0;
            v5 = (result < ((__int64 *)a1)[2]) ? 1 : 0;
            if (result == ((__int64 *)a1)[2]) v5 = a4;
            if (v5 == 1) {
                a4 = ((__int64 *)a1)[2];
                ((__int64 *)a1)[3] = (__int64)(a4);
                a4 = 0;
                a4 = (a3 < ((__int64 *)a1)[1]) ? 1 : 0;
                v5 = 0;
                v5 = (result < a1->field_8) ? 1 : 0;
                if (result == a1->field_8) v5 = a4;
                if (v5 != 1) {
                    a4 = a1 + 16;
                } else {
                    a4 = a1->field_8;
                    ((__int64 *)a1)[2] = (__int64)(a4);
                    a4 = 0;
                    a4 = (a3 < a1->field_4) ? 1 : 0;
                    v5 = 0;
                    v5 = (result < a1->field_0) ? 1 : 0;
                    if (result == a1->field_0) v5 = a4;
                    if (v5 != 1) {
                        a4 = a1 + 8;
                    } else {
                        a4 = a1->field_0;
                        a1->field_8 = a4;
                        a4 = (int *)a1;
                    }
                }
                a3 <<= 32;
                a3 |= result;
                *a4 = a3;
            }
            if (a2 != 4) {
                result = ((__int64 *)a1)[4];
                a2 = ((__int64 *)a1)[4];
                a3 = 0;
                a3 = (a2 < ((__int64 *)a1)[3]) ? 1 : 0;
                a4 = 0;
                a4 = (result < ((__int64 *)a1)[3]) ? 1 : 0;
                if (result == ((__int64 *)a1)[3]) a4 = a3;
                if (a4 == 1) {
                    v2 = ((__int64 *)a1)[3];
                    ((__int64 *)a1)[4] = (__int64)(v2);
                    a3 = 0;
                    a3 = (a2 < ((__int64 *)a1)[2]) ? 1 : 0;
                    a4 = 0;
                    a4 = (result < ((__int64 *)a1)[2]) ? 1 : 0;
                    if (result == ((__int64 *)a1)[2]) a4 = a3;
                    if (a4 != 1) {
                        a1 += 24;
                    } else {
                        v3 = ((__int64 *)a1)[2];
                        ((__int64 *)a1)[3] = (__int64)(v3);
                        a3 = 0;
                        a3 = (a2 < ((__int64 *)a1)[1]) ? 1 : 0;
                        a4 = 0;
                        a4 = (result < a1->field_8) ? 1 : 0;
                        if (result == a1->field_8) a4 = a3;
                        if (a4 != 1) {
                            a1 += 16;
                        } else {
                            v4 = a1->field_8;
                            ((__int64 *)a1)[2] = (__int64)(v4);
                            a3 = 0;
                            a3 = (a2 < a1->field_4) ? 1 : 0;
                            a4 = 0;
                            a4 = (result < a1->field_0) ? 1 : 0;
                            if (result == a1->field_0) a4 = a3;
                            if (a4 != 1) {
                                a1 += 8;
                            } else {
                                v5 = a1->field_0;
                                a1->field_8 = v5;
                            }
                        }
                    }
                    a2 <<= 32;
                    a2 |= result;
                    *(__int64 *)a1 = (__int64)(a2);
                }
            }
        }
    }
    return result;
}