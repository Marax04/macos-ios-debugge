// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `a2`
struct Struct_2_t {
    char field_0; // offset 0
    int field_1; // offset 1
    char _pad_1[3];
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F3510();
__int64 sub_1400F5F90();

__int64 __fastcall sub_1400F1490(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    __int64 v6;
    __int64 i;
    __int64 v1;
    int v11;
    __int64 *src;
    __int64 v5;
    __int64 *src2;
    __int64 v7;
    __int64 *src3;
    struct Struct_3_t *ptr;
    __int64 v4;

    v6 = a1->field_0;
    i = ((__int64 *)a1)[2];
    if (a2->field_0 != 1) {
        v1 = a2->field_1;
        v11 = ((__int64 *)a1)[15];
        if (i == v6) {
            src = (__int64 *)a1;
            sub_1400F3510(src);
            v6 = *src;
        }
        a2 = a1->field_8;
        *(__int64 *)(a2 + i) = (__int64)(v11);
        v5 = i + 1;
        ((__int64 *)a1)[2] = (__int64)(v5);
        v1 = *(__int64 *)(a1 + v1 + 616);
        if (v5 == v6) {
            src2 = (__int64 *)a1;
            sub_1400F3510(src2);
            a2 = *(src2 + 8);
        }
        *(__int64 *)(a2 + i + 1) = (__int64)(v1);
        i += 2;
    } else {
        v7 = a2->field_8;
        v11 = ((__int64 *)a1)[15];
        if (i == v6) {
            src3 = (__int64 *)a1;
            sub_1400F3510(a1, a2, v4);
            v6 = *src3;
        }
        a2 = a1->field_8;
        *(__int64 *)(a2 + i) = (__int64)(v11);
        ++i;
        ((__int64 *)a1)[2] = (__int64)(i);
        v6 -= i;
        if (v6 <= 7) {
            ptr = (struct Struct_3_t *)a1;
            sub_1400F5F90(ptr, i, 8);
            a1 = (struct Struct_1_t *)ptr;
            a2 = ptr->field_8;
            i = ptr->field_10;
        }
        *(__int64 *)(a2 + i) = (__int64)(v7);
        i += 8;
    }
    ((__int64 *)a1)[2] = (__int64)(i);
    return i;
}