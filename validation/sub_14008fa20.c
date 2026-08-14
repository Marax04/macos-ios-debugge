// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 4 accesses on `i`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    int field_12; // offset 18
    char _pad_12[2];
    __int64 field_18; // offset 24
};

// inferred from 3 accesses on `ptr`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2];
    __int64 field_12; // offset 18
};

__int64 sub_14008FC27();
__int64 sub_140018B70();
__int64 sub_14008FC42();
__int64 sub_14008FC45();
extern __int64 off_140118AE2;
extern __int64 off_140110A3A;
extern __int64 off_140118AEA;
extern __int64 off_140117BCE;
extern __int64 off_14011F158;
extern __int64 off_14011F2E0;
extern __int64 off_14008FC60;
extern __int64 off_140118AEE;
extern __int64 off_140110A3D;

__int64 __fastcall sub_14008FA20(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    __int64 v_20;
    __int64 v_30;
    int v_38;
    int v_39;
    int *v_0;
    char *str;
    struct Struct_3_t *ptr;
    __int64 *src;
    __int64 v6;
    struct Struct_2_t *i;
    __int64 v7;
    int v2;
    __int64 v5;

    ptr = (struct Struct_3_t *)a2;
    src = a1;
    str = (char *)a1;
    v6 = a2->field_0;
    i = a2->field_8;
    v7 = i->field_18;
    a2 = &off_140118AE2;
    ((__int64 (*)())v7)(v6, a2, 8);
    v_30 = (__int64)ptr;
    v2 = 1;
    if (i == 0) {
        if ((ptr->field_12 & 128) != 0) JUMPOUT(0x14008fb6a);
        a2 = &off_140110A3A;
        ((__int64 (*)())v7)(v6, a2, 3);
        v2 = 1;
        if (i == 0) {
            a1 = ptr->field_0;
            i = ptr->field_8;
            a2 = &off_140118AEA;
            v5 = 4;
            ((__int64 (*)())(i->field_18))();
            if (i == 0) {
                a1 = ptr->field_0;
                i = ptr->field_8;
                a2 = &off_140117BCE;
                v5 = 2;
                ((__int64 (*)())(i->field_18))();
                if (i == 0) {
                    i = *(src + 1);
                    ++i;
                    a1 = &off_14011F158;
                    v5 = v_0[(__int64)i];
                    a1 = &off_14011F2E0;
                    a2 = v_0[(__int64)i];
                    a2 = (struct Struct_1_t *)((__int64)a2 + (__int64)a1);
                    a1 = ptr->field_0;
                    i = ptr->field_8;
                    ((__int64 (*)())(i->field_18))();
                    return sub_14008FC27();
                }
            }
        }
    }
    v_38 = v2;
    v_39 = 1;
    i = &off_14008FC60;
    v_20 = (__int64)i;
    a2 = &off_140118AEE;
    a1 = rsp + 48;
    sub_140018B70(a1, a2, 4, str);
    a1 = (__int64 *)v_38;
    i = (struct Struct_2_t *)v_39;
    a2 = (struct Struct_1_t *)i;
    a2 = (struct Struct_1_t *)(~(__int64)a2);
    a2 = (struct Struct_1_t *)((__int64)(__int64)a2 | (__int64)a1);
    if (((__int64)a2 & 1) == 0) {
        i = (struct Struct_2_t *)v_30;
        if ((i->field_12 & 128) != 0) JUMPOUT(0x14008fc2e);
        a1 = i->field_0;
        i = i->field_8;
        a2 = &off_140110A3D;
        v5 = 2;
        return sub_14008FC42();
    } else {
        i = (struct Struct_2_t *)((__int64)(__int64)i | (__int64)a1);
        return sub_14008FC45();
    }
}