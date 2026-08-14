// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    char _pad_0[3];
    char field_7; // offset 7
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140017B60();
__int64 sub_14002E830();
__int64 off_140108090();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14012D098;

__int64 __fastcall sub_1400371B0(int *a1, __int64 a2) {
    int v_10;
    __int64 v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_48;
    int v_50;
    int v_8;
    char *str;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v7;
    __int64 v2;
    __int64 v8;
    __int64 *src;
    __int64 v4;
    __int64 v9;
    __int64 v10;
    int v1;

    v_8 = -2;
    ptr = (struct Struct_1_t *)a1;
    v5 = a2 - 1;
    v7 = str - 56;
    sub_140017B60(v7, ptr, v5);
    if (v_38 == 0) {
        a2 = v_30;
        v2 = v_28;
        v8 = str - 80;
        sub_14002E830(v8, a2, v2);
        src = (__int64 *)v_50;
        ptr = (struct Struct_1_t *)src;
        ptr = (struct Struct_1_t *)(-(__int64)ptr);
        if ((0 /* overflow check on (-ptr) */)) {
            v4 = v_48;
            off_140108090();
            ((__int64 (*)())v2)(ptr, v4, off_14012D098);
            if (src != 0) {
                off_140108030();
                off_140108038(ptr, 0, v4);
            }
        } else {
            ptr = (struct Struct_1_t *)v_48;
            a1 = (int *)v1;
            a1 = (int *)((__int64)(__int64)a1 & 3);
            if (a1 == 1) {
                v9 = ptr - 1;
                v_10 = v9;
                v10 = *(__int64 *)(ptr - 1);
                v_20 = v10;
                ptr = ptr->field_7;
                v_18 = (__int64)ptr;
                ptr = ptr->field_0;
                if (ptr != 0) {
                    ((__int64 (*)())ptr)(v_20);
                }
                src = (__int64 *)v_20;
                ptr = (struct Struct_1_t *)v_18;
                if (ptr->field_8 == 0) {
                    v4 = v_10;
                } else {
                    if (ptr->field_10 >= 17) {
                        src = *(src - 8);
                    }
                    v4 = v_10;
                    off_140108030();
                    off_140108038(ptr, 0, src);
                }
                return v4;
            }
        }
    }
    return v4;
}