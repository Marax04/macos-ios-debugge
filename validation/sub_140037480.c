// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
    char _pad_18[88];
    __int64 field_78; // offset 120
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F7210();
__int64 sub_14002DFB0();
__int64 sub_1400377D0();
__int64 sub_140037910();
__int64 sub_140037A70();
extern __int64 off_14012D270;
extern __int64 off_140037740;
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_140037480(__int64 *a1) {
    int arg_8;
    __int64 v_18;
    int v_20;
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    __int64 v_40;
    __int64 v_48;
    int v_50;
    __int64 v_58;
    int str;
    int v_9;
    int v_a;
    __int64 *v_0;
    char *str2;
    __int64 v5;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 *src;
    __int64 v2;

    str = -2;
    v_50 = (int)a1;
    v5 = a1[3];
    v_40 = v5;
    v_48 = 1;
    ptr = off_14012D270;
    a1 = __readgsqword(88);
    ptr = v_0[(__int64)ptr];
    ptr2 = ptr + 112;
    ptr = ptr->field_78;
    if (ptr != 1) {
        if (ptr == 2) {
            v_9 = 1;
            sub_1400F7210(a1);
        }
        v_9 = 1;
        src = &off_140037740;
        sub_14002DFB0(ptr2, src);
        ptr2->field_8 = 1;
    }
    ptr = ptr2->field_0;
    v_18 = (__int64)ptr;
    *(__int64 *)ptr2 = (__int64)(v5);
    a1 = str2 - 24;
    sub_1400377D0(a1);
    ptr = (struct Struct_1_t *)v_18;
    if (ptr != 0) {
        *(__int64 *)ptr = (__int64)(ptr->field_0 - 1);
        if (!((ptr->field_0 != 0))) {
            v_9 = 0;
            a1 = str2 - 24;
            sub_140037910(a1);
        }
    }
    a1 = (__int64 *)v_50;
    ptr = *a1;
    src = (__int64 *)arg_8;
    a1 = a1[2];
    ptr2 = (struct Struct_2_t *)a1;
    ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 << 4);
    ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)src);
    v_48 = (__int64)src;
    v_38 = (__int64)ptr;
    v_30 = (__int64)ptr2;
    if (a1 != 0) {
        src += 16;
        v5 = off_140108030;
        v2 = off_140108038;
        do {
            a1 = *(src - 16);
            v_58 = (__int64)src;
            ptr = *(src - 8);
            v_20 = (int)a1;
            v_28 = (__int64)ptr;
            ((__int64 (*)())(ptr->field_18))();
            ptr = (struct Struct_1_t *)v_28;
            src = (__int64 *)v_58;
            ptr = src - 16;
            src += 16;
            ptr += 16;
        } while (ptr != ptr2);
    }
    v_40 = (__int64)src;
    v_a = 0;
    a1 = str2 - 72;
    return sub_140037A70(a1, ptr2);
}