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

// inferred from 2 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

// inferred from 2 accesses on `ptr2`
struct Struct_4_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_1400F27FC();
extern __int64 off_14012149C;

__int64 __fastcall sub_14002D560(struct Struct_1_t *a1,struct Struct_2_t *a2, int a3, size_t a4) {
    __int64 v5;
    __int64 result;
    __int64 v6;
    __int64 *src;
    __int64 v8;
    struct Struct_3_t *ptr;
    struct Struct_4_t *ptr2;
    __int64 v2;

    a3 = a1->field_0;
    v5 = a3 - 5;
    result = 0;
    if (a3 < 6) v5 = result;
    a4 = a2->field_0;
    v6 = a4 - 5;
    if (a4 < 6) v6 = result;
    if (v5 == v6) {
        result = 1;
        if (v5 == 0) {
            if (a4 <= 5) {
                if (a3 == a4) {
                    result = a3;
                    src = &off_14012149C;
                    result = *(src + result*4);
                    result += (__int64)src;
                    JUMPOUT(result);
                    v8 = ((__int64 *)a1)[2];
                    if (v8 == ((__int64 *)a2)[2]) {
                        ptr = (struct Struct_3_t *)a2;
                        a2 = a2->field_8;
                        ptr2 = (struct Struct_4_t *)a1;
                        a1 = a1->field_8;
                        sub_1400F27FC(a1, a2, v8);
                        if (result == 0) {
                            v2 = ptr2->field_20;
                            if (v2 != ptr->field_20) {
                                result = 0;
                            } else {
                                a2 = ptr->field_18;
                                a1 = ptr2->field_18;
                                sub_1400F27FC(a1, a2, v2, a4);
                                result = (result == 0) ? 1 : 0;
                            }
                            return result;
                        }
                    }
                }
                return result;
            }
        } else {
            if (v5 == 4) {
                v2 = ((__int64 *)a1)[2];
                if (v2 != ((__int64 *)a2)[2]) {
                    return v2;
                } else {
                    a2 = a2->field_8;
                    a1 = a1->field_8;
                    return (__int64)a1;
                }
            }
        }
    }
    return result;
}