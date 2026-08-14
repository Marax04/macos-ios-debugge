// inferred from 4 accesses on `a2`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[24];
    __int64 field_30; // offset 48
    char field_38; // offset 56
    __int64 field_39; // offset 57
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    char _pad_20[18];
    __int64 field_3A; // offset 58
};

__int64 sub_14002D24F();

__int64 __fastcall sub_14002D130(__int64 *a1,struct Struct_1_t *a2, __int64 a3, size_t a4) {
    int arg_7;
    int v_10;
    int v_14;
    int v_8;
    __int64 v2;
    struct Struct_2_t *ptr;
    __int64 v10;
    __int64 result;
    __int64 v5;
    __int64 v9;
    __int64 v8;
    __int64 *v3;
    __int64 i;
    __int64 v6;

    v2 = a2->field_38;
    if (v2 != 3) {
        ptr = (struct Struct_2_t *)a2;
        v10 = a2->field_39;
        a4 = a2->field_10;
        a3 = 0;
        result = (a4 >= 3) ? 1 : 0;
        v5 = a2->field_30;
        a2 = v5 + 1;
        if (v5 == 0) a2 = v5;
        if (v10 != 3) {
            v2 = ptr->field_20;
            v9 = v2 + 4;
            a3 = result;
            result = a3 + a3*2;
            result += 7;
            v_14 = result;
            result = ptr->field_3A;
            arg_7 = result;
            v8 = v2 + a2 + 2;
            result = v2 + a2 + 8;
            v_8 = result;
            v3 = ptr->field_0;
            i = ptr->field_8;
            v5 = *a1;
            result = a4;
            v_10 = result;
            v6 = i;
            if (v2 <= v10) {
                v10 = v6;
                if (v2 == 0) JUMPOUT(0x14002d310);
                result = v2;
                if (v2 == 1) JUMPOUT(0x14002d270);
                if (v10 == 0) JUMPOUT(0x14002d42d);
                a3 = 0;
                if (a4 >= 3) JUMPOUT(0x14002d230);
                do {
                    if (*(v3 + i) == 92) JUMPOUT(0x14002d331);
                    ++i;
                } while (v10 != i);
                return sub_14002D24F();
            }
        }
    }
    *a1 = 10;
    return result;
}