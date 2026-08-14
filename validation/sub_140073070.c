// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

extern __int64 off_14011EC78;
extern __int64 off_14011ECA8;
extern __int64 off_14011EC90;
extern __int64 off_14011ECC0;
extern __int64 off_14011ECD8;
extern __int64 off_14011ECF0;

__int64 __fastcall sub_140073070(struct Struct_1_t *a1, int *a2, int *a3, size_t a4) {
    struct Struct_2_t *ptr;
    struct Struct_3_t *ptr2;
    __int64 *v2;
    __int64 v9;
    __int64 v8;
    __int64 v10;
    __int64 result;
    __int64 *v5;
    __int64 *v6;
    __int64 *v_cap;
    __int64 v_cap3;
    __int64 *v_cap2;
    __int64 *v7;

    ptr = (struct Struct_2_t *)a3;
    ptr2 = (struct Struct_3_t *)a2;
    if (a4 >= 8) {
        a4 >>= 3;
        v2 = a4 * 352;
        a2 = (__int64)a1 + (__int64)v2;
        v9 = a4 * 616;
        v8 = a1 + v9;
        v10 = a4;
        sub_140073070(a1, a2, v8, a4);
        a2 = (__int64)ptr2 + (__int64)v2;
        a3 = ptr2 + v9;
        sub_140073070(ptr2, a2, a3, v10);
        ptr2 = (struct Struct_3_t *)result;
        v2 = (__int64 *)((__int64)v2 + (__int64)ptr);
        v9 += (__int64)ptr;
        sub_140073070(ptr, v2, v9, v10);
        ptr = (struct Struct_2_t *)result;
        a1 = (struct Struct_1_t *)result;
    }
    a4 = a1->field_0;
    a3 = 80;
    result = a4;
    result = -result;
    a2 = 80;
    if ((0 /* overflow check on (-result) */)) {
        result = *(v_cap2 + 8);
        a2 = result - 3;
        if (a2 >= 2) result = a2;
        a2 = &off_14011EC78;
        a2 = a2[result];
        result = ptr2->field_0;
        v5 = (__int64 *)result;
        v5 = (__int64 *)(-(__int64)v5);
        if ((0 /* overflow check on (-v5) */)) {
            a4 = -a4;
            v5 = 80;
            a4 = 80;
            if (!((0 /* overflow check on (-a4) */))) {
                a4 = a1->field_8;
                v6 = a4 - 3;
                v_cap = 2;
                if (v6 >= 2) v_cap = v6;
                v6 = &off_14011ECA8;
                v_cap = v6[(__int64)v_cap];
            }
        } else {
            a3 = ptr2->field_8;
            v5 = a3 - 3;
            v_cap3 = 2;
            if (v5 >= 2) v_cap3 = v5;
            v5 = &off_14011EC90;
            v_cap3 = v5[v_cap3];
            v_cap = (__int64 *)(-(__int64)v_cap);
            v5 = 80;
            v_cap = 80;
            if ((0 /* overflow check on (-v_cap) */)) {
                return (__int64)v_cap;
            } else {
            }
        }
        a2 = *(__int64 *)((__int64)a1 + (__int64)a2);
        a3 = *(__int64 *)((__int64)ptr2 + (__int64)a3);
        v6 = *(__int64 *)((__int64)a1 + (__int64)v_cap);
        v_cap = ptr->field_0;
        v2 = v_cap;
        v2 = (__int64 *)(-(__int64)v2);
        if (!((0 /* overflow check on (-v2) */))) {
            v5 = ptr->field_8;
            v2 = v5 - 3;
            if (v2 >= 2) v5 = v2;
            v2 = &off_14011ECC0;
            v5 = v2[(__int64)v5];
        }
        v2 = (a2 < a3) ? 1 : 0;
        v5 = (v6 < *(__int64 *)((__int64)ptr + (__int64)v5)) ? 1 : 0;
        v5 = (__int64 *)((__int64)(__int64)v5 ^ (__int64)v2);
        if (!((v5 != 0))) {
            result = -result;
            result = 80;
            a1 = 80;
            if (!((0 /* overflow check on (-result) */))) {
                a1 = ptr2->field_8;
                v5 = a1 - 3;
                v_cap2 = 2;
                if (v5 >= 2) v_cap2 = v5;
                v7 = &off_14011ECD8;
                v_cap2 = v7[(__int64)v_cap2];
            }
            v_cap = (__int64 *)(-(__int64)v_cap);
            v_cap2 = *(__int64 *)((__int64)ptr2 + (__int64)v_cap2);
            if (!((0 /* overflow check on (-v_cap) */))) {
                result = ptr->field_8;
                v_cap = result - 3;
                if (v_cap >= 2) result = v_cap;
                v_cap = &off_14011ECF0;
                result = v_cap[result];
            }
            a2 = (a2 < a3) ? 1 : 0;
            result = (v_cap2 < *(__int64 *)(ptr + result)) ? 1 : 0;
            result ^= (__int64)a2;
            if (result != 0) ptr2 = ptr;
            v_cap2 = (__int64 *)ptr2;
        }
        result = (__int64)v_cap2;
        return result;
    } else {
        result = ptr2->field_0;
        v5 = (__int64 *)result;
        v5 = (__int64 *)(-(__int64)v5);
        if ((0 /* overflow check on (-v5) */)) {
            return (__int64)v5;
        } else {
            return (__int64)v5;
        }
        return (__int64)v5;
    }
    return result;
}