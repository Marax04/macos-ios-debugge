// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F37D0();
__int64 sub_1400F3570();
extern __int64 off_14010ADC0;
extern __int64 off_14010AEB8;

__int64 __fastcall sub_140010C90(struct Struct_1_t *a1) {
    __int64 *dst;
    __int64 i;
    __int64 v5;
    struct Struct_2_t *ptr;
    int v2;

    dst = a1->field_8;
    i = ((__int64 *)a1)[2];
    if (i <= 1) {
        if ((0 /* unresolved: flags != */)) {
            a1 = &off_14010ADC0;
            v5 = &off_14010AEB8;
            sub_1400F37D0(a1, 42, v5);
        } else {
            ((__int64 *)a1)[2] = (__int64)(0);
            if (a1->field_0 == 0) {
                ptr = (struct Struct_2_t *)a1;
                sub_1400F3570(a1, 0, 1);
                a1 = (struct Struct_1_t *)ptr;
                dst = ptr->field_8;
                i = ptr->field_10;
            } else {
                v2 = 0;
            }
            *(dst + i) = 83;
            ++i;
            ((__int64 *)a1)[2] = (__int64)(i);
            return i;
        }
        return i;
    } else {
        if (*(dst + 1) > 191) {
            *dst = 83;
            ((__int64 *)a1)[2] = (__int64)(i);
            return i;
        }
    }
    return i;
}