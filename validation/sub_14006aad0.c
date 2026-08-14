// inferred from 3 accesses on `a1`
struct Struct_1_t {
    int field_0; // offset 0
    int field_4; // offset 4
    __int64 field_8; // offset 8
};

// inferred from 15 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[4];
    int field_4; // offset 4
    int field_8; // offset 8
    int field_C; // offset 12
    int field_10; // offset 16
    int field_14; // offset 20
    int field_18; // offset 24
    int field_1C; // offset 28
    int field_20; // offset 32
    int field_24; // offset 36
    int field_28; // offset 40
    int field_2C; // offset 44
    int field_30; // offset 48
    int field_34; // offset 52
    int field_38; // offset 56
    __int64 field_3C; // offset 60
};

int __fastcall sub_14006AAD0(struct Struct_1_t *a1, int *a2) {
    int v_4;
    int v_8;
    int v_c;
    struct Struct_2_t *ptr;
    int result;
    int v11;
    int v7;
    int v2;
    int v10;
    int v4;
    int v3;
    int v12;
    int v8;
    int v13;
    int v9;
    int v5;

    ptr = (struct Struct_2_t *)a2;
    result = ((__int64 *)a1)[2];
    v11 = a1->field_0;
    v7 = a1->field_4;
    v11 += *a2;
    v11 += result;
    v2 = ((__int64 *)a1)[6];
    v2 ^= v11;
    v2 = __ROL4__(v2, 16);
    a2 = ((__int64 *)a1)[4];
    a2 += v2;
    v_4 = (int)a2;
    result ^= (__int64)a2;
    result = __ROL4__(result, 20);
    v_8 = result;
    v11 += ptr->field_4;
    v11 += result;
    v10 = ((__int64 *)a1)[2];
    v7 += ptr->field_8;
    v7 += v10;
    v4 = ((__int64 *)a1)[6];
    v4 ^= v7;
    v4 = __ROL4__(v4, 16);
    result = ((__int64 *)a1)[4];
    result += v4;
    v10 ^= result;
    v10 = __ROL4__(v10, 20);
    v7 += ptr->field_C;
    v7 += v10;
    v4 ^= v7;
    v4 = __ROL4__(v4, 24);
    result += v4;
    v_c = result;
    v10 ^= result;
    v10 = __ROL4__(v10, 25);
    v3 = a1->field_8;
    v12 = ((__int64 *)a1)[3];
    v3 += ptr->field_10;
    v3 += v12;
    v8 = ((__int64 *)a1)[7];
    v8 ^= v3;
    v8 = __ROL4__(v8, 16);
    a2 = ((__int64 *)a1)[5];
    a2 += v8;
    v12 ^= (__int64)a2;
    v12 = __ROL4__(v12, 20);
    v2 ^= v11;
    v3 += ptr->field_14;
    v3 += v12;
    v8 ^= v3;
    v8 = __ROL4__(v8, 24);
    v13 = ((__int64 *)a1)[1];
    v13 += ptr->field_18;
    v9 = ((__int64 *)a1)[3];
    v13 += v9;
    result = ((__int64 *)a1)[7];
    result ^= v13;
    result = __ROL4__(result, 16);
    a2 += v8;
    v5 = ((__int64 *)a1)[5];
    v5 += result;
    v9 ^= v5;
    v9 = __ROL4__(v9, 20);
    v13 += ptr->field_1C;
    v13 += v9;
    result ^= v13;
    result = __ROL4__(result, 24);
    v12 ^= (__int64)a2;
    v11 += v10;
    v11 += ptr->field_20;
    v5 += result;
    result ^= v11;
    result = __ROL4__(result, 16);
    a2 += result;
    v10 ^= (__int64)a2;
    v10 = __ROL4__(v10, 20);
    v11 += ptr->field_24;
    v11 += v10;
    *(__int64 *)a1 = (__int64)(v11);
    v11 ^= result;
    v11 = __ROL4__(v11, 24);
    ((__int64 *)a1)[7] = (__int64)(v11);
    v11 += (__int64)a2;
    ((__int64 *)a1)[5] = (__int64)(v11);
    v11 ^= v10;
    v11 = __ROL4__(v11, 25);
    ((__int64 *)a1)[2] = (__int64)(v11);
    v2 = __ROL4__(v2, 24);
    v12 = __ROL4__(v12, 25);
    result = v_4;
    result += v2;
    v7 += v12;
    v7 += ptr->field_28;
    v9 ^= v5;
    v2 ^= v7;
    v2 = __ROL4__(v2, 16);
    v5 += v2;
    v12 ^= v5;
    v12 = __ROL4__(v12, 20);
    v7 += ptr->field_2C;
    v7 += v12;
    a1->field_4 = v7;
    v7 ^= v2;
    v7 = __ROL4__(v7, 24);
    ((__int64 *)a1)[6] = (__int64)(v7);
    v7 += v5;
    ((__int64 *)a1)[5] = (__int64)(v7);
    v7 ^= v12;
    a2 = (int *)v_8;
    a2 = (int *)((__int64)(__int64)a2 ^ result);
    v9 = __ROL4__(v9, 25);
    v7 = __ROL4__(v7, 25);
    v3 += v9;
    v3 += ptr->field_30;
    v4 ^= v3;
    v4 = __ROL4__(v4, 16);
    result += v4;
    v9 ^= result;
    v9 = __ROL4__(v9, 20);
    v3 += ptr->field_34;
    ((__int64 *)a1)[3] = (__int64)(v7);
    v3 += v9;
    a1->field_8 = v3;
    v3 ^= v4;
    v3 = __ROL4__(v3, 24);
    ((__int64 *)a1)[6] = (__int64)(v3);
    v3 += result;
    ((__int64 *)a1)[4] = (__int64)(v3);
    v3 ^= v9;
    result = (int)a2;
    result = __ROL4__(result, 25);
    v13 += result;
    v13 += ptr->field_38;
    v8 ^= v13;
    v13 += ptr->field_3C;
    v3 = __ROL4__(v3, 25);
    ((__int64 *)a1)[3] = (__int64)(v3);
    v8 = __ROL4__(v8, 16);
    a2 = (int *)v_c;
    a2 += v8;
    result ^= (__int64)a2;
    result = __ROL4__(result, 20);
    v13 += result;
    ((__int64 *)a1)[1] = (__int64)(v13);
    v13 ^= v8;
    v13 = __ROL4__(v13, 24);
    ((__int64 *)a1)[7] = (__int64)(v13);
    v13 += (__int64)a2;
    ((__int64 *)a1)[4] = (__int64)(v13);
    v13 ^= result;
    v13 = __ROL4__(v13, 25);
    ((__int64 *)a1)[2] = (__int64)(v13);
    return result;
}