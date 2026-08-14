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

__int64 __fastcall sub_140058230(struct Struct_1_t *a1,struct Struct_2_t *a2) {
    __int64 result;
    __int64 v2;

    result = a1->field_0;
    v2 = a2->field_0;
    *(__int64 *)a1 = (__int64)(v2);
    *(__int64 *)a2 = (__int64)(result);
    result = a1->field_8;
    v2 = a2->field_8;
    a1->field_8 = v2;
    a2->field_8 = result;
    result = ((__int64 *)a1)[2];
    v2 = ((__int64 *)a2)[2];
    ((__int64 *)a1)[2] = (__int64)(v2);
    ((__int64 *)a2)[2] = (__int64)(result);
    result = ((__int64 *)a1)[3];
    v2 = ((__int64 *)a2)[3];
    ((__int64 *)a1)[3] = (__int64)(v2);
    ((__int64 *)a2)[3] = (__int64)(result);
    result = ((__int64 *)a1)[4];
    v2 = ((__int64 *)a2)[4];
    ((__int64 *)a1)[4] = (__int64)(v2);
    ((__int64 *)a2)[4] = (__int64)(result);
    result = ((__int64 *)a1)[5];
    v2 = ((__int64 *)a2)[5];
    ((__int64 *)a1)[5] = (__int64)(v2);
    ((__int64 *)a2)[5] = (__int64)(result);
    result = ((__int64 *)a1)[6];
    v2 = ((__int64 *)a2)[6];
    ((__int64 *)a1)[6] = (__int64)(v2);
    ((__int64 *)a2)[6] = (__int64)(result);
    result = ((__int64 *)a1)[7];
    v2 = ((__int64 *)a2)[7];
    ((__int64 *)a1)[7] = (__int64)(v2);
    ((__int64 *)a2)[7] = (__int64)(result);
    result = ((__int64 *)a1)[8];
    v2 = ((__int64 *)a2)[8];
    ((__int64 *)a1)[8] = (__int64)(v2);
    ((__int64 *)a2)[8] = (__int64)(result);
    result = ((__int64 *)a1)[9];
    v2 = ((__int64 *)a2)[9];
    ((__int64 *)a1)[9] = (__int64)(v2);
    ((__int64 *)a2)[9] = (__int64)(result);
    result = ((__int64 *)a1)[10];
    v2 = ((__int64 *)a2)[10];
    ((__int64 *)a1)[10] = (__int64)(v2);
    ((__int64 *)a2)[10] = (__int64)(result);
    result = ((__int64 *)a1)[11];
    v2 = ((__int64 *)a2)[11];
    ((__int64 *)a1)[11] = (__int64)(v2);
    ((__int64 *)a2)[11] = (__int64)(result);
    result = ((__int64 *)a1)[12];
    v2 = ((__int64 *)a2)[12];
    ((__int64 *)a1)[12] = (__int64)(v2);
    ((__int64 *)a2)[12] = (__int64)(result);
    result = ((__int64 *)a1)[13];
    v2 = ((__int64 *)a2)[13];
    ((__int64 *)a1)[13] = (__int64)(v2);
    ((__int64 *)a2)[13] = (__int64)(result);
    result = ((__int64 *)a1)[14];
    v2 = ((__int64 *)a2)[14];
    ((__int64 *)a1)[14] = (__int64)(v2);
    ((__int64 *)a2)[14] = (__int64)(result);
    result = ((__int64 *)a1)[15];
    v2 = ((__int64 *)a2)[15];
    ((__int64 *)a1)[15] = (__int64)(v2);
    ((__int64 *)a2)[15] = (__int64)(result);
    result = ((__int64 *)a1)[16];
    v2 = ((__int64 *)a2)[16];
    ((__int64 *)a1)[16] = (__int64)(v2);
    ((__int64 *)a2)[16] = (__int64)(result);
    result = ((__int64 *)a1)[17];
    v2 = ((__int64 *)a2)[17];
    ((__int64 *)a1)[17] = (__int64)(v2);
    ((__int64 *)a2)[17] = (__int64)(result);
    result = ((__int64 *)a1)[18];
    v2 = ((__int64 *)a2)[18];
    ((__int64 *)a1)[18] = (__int64)(v2);
    ((__int64 *)a2)[18] = (__int64)(result);
    result = ((__int64 *)a1)[19];
    v2 = ((__int64 *)a2)[19];
    ((__int64 *)a1)[19] = (__int64)(v2);
    ((__int64 *)a2)[19] = (__int64)(result);
    result = ((__int64 *)a1)[20];
    v2 = ((__int64 *)a2)[20];
    ((__int64 *)a1)[20] = (__int64)(v2);
    ((__int64 *)a2)[20] = (__int64)(result);
    return result;
}