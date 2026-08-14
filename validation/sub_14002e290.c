// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    char _pad_0[3];
    __int64 field_7; // offset 7
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002E830();
__int64 sub_14002E3DF();
__int64 sub_14002E5CA();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_14002E290(int *a1, __int64 a2) {
    int arg_3e8;
    int arg_3f0;
    int arg_3f8;
    int arg_400;
    int arg_408;
    __int64 arg_410;
    __int64 arg_418;
    int arg_420;
    int v_48;
    int v_50;
    char *str;
    __int64 *dst;
    __int64 v6;
    __int64 v10;
    __int64 v5;
    int v1;
    __int64 *src;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 v9;

    arg_420 = -2;
    dst = (__int64 *)a1;
    a1 = str - 80;
    sub_14002E830(a1);
    a1 = (int *)v_50;
    v6 = (__int64)a1;
    v6 = -v6;
    if ((0 /* overflow check on (-v6) */)) {
        arg_410 = (__int64)dst;
        arg_400 = (int)a1;
        v10 = v_48;
        arg_408 = v10;
        arg_3e8 = 0;
        arg_3f0 = 2;
        arg_3f8 = 0;
        v5 = 512;
        v1 = 2;
        arg_418 = v10;
        dst = 0;
        src = 0;
        v10 = 0;
        if (v5 >= 513) JUMPOUT(0x14002e3f0);
        return sub_14002E3DF();
    } else {
        ptr = (struct Struct_1_t *)v_48;
        a1 = (int *)v1;
        a1 = (int *)((__int64)(__int64)a1 & 3);
        if (a1 == 1) {
            a1 = ptr - 1;
            arg_400 = (int)a1;
            a1 = *(__int64 *)(ptr - 1);
            arg_408 = (int)a1;
            ptr = ptr->field_7;
            arg_418 = (__int64)ptr;
            ptr = ptr->field_0;
            if (ptr != 0) {
                a1 = (int *)arg_408;
                ((__int64 (*)())ptr)(a1);
            }
            src = (__int64 *)arg_408;
            ptr2 = (struct Struct_2_t *)arg_418;
            if (ptr2->field_8 != 0) {
                if (ptr2->field_10 >= 17) {
                    src = *(src - 8);
                }
                off_140108030();
                off_140108038(ptr2, 0, src);
            }
            off_140108030();
            off_140108038(ptr2, 0, arg_400);
        }
        v9 = 0x8000000000000000;
        *dst = v9;
        return sub_14002E5CA();
    }
}