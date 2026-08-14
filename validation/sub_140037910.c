// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140037910(__int64 *a1, __int64 a2) {
    __int64 v_10;
    __int64 v_18;
    int v_20;
    int v_8;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 *src;
    struct Struct_2_t *ptr2;
    __int64 *src2;
    __int64 *result;
    __int64 v9;
    __int64 *dst;
    __int64 v10;
    __int64 v5;

    v_8 = -2;
    ptr = *a1;
    v7 = ptr->field_10;
    v_20 = v7;
    v_10 = (__int64)ptr;
    ptr = ptr->field_18;
    v_18 = (__int64)ptr;
    ptr = ptr->field_0;
    if (ptr != 0) {
        ((__int64 (*)())ptr)(v_20);
    }
    src = (__int64 *)v_20;
    ptr2 = (struct Struct_2_t *)v_18;
    src2 = (__int64 *)v_10;
    if (ptr2->field_8 != 0) {
        if (ptr2->field_10 >= 17) {
            src = *(src - 8);
        }
        off_140108030();
        ((__int64 (*)())off_140108038)(ptr2, 0, src);
    }
    result = *(src2 + 32);
    if (result != 0) {
        *result = *result - 1;
        if (!((*result != 0))) {
            result = (__int64 *)v_10;
            v9 = result + 32;
            sub_140037910(v9, a2);
        }
    }
    dst = (__int64 *)v_10;
    if (dst != -1) {
        *(dst + 8) = *(dst + 8) - 1;
        if (!((*(dst + 8) != 0))) {
            off_140108030();
            v10 = (__int64)result;
            a2 = 0;
            v5 = (__int64)dst;
            JUMPOUT(off_140108038);
        }
    }
    return (__int64)result;
}