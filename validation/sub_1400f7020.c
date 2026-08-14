// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140033EF0();
__int64 sub_140034180();
__int64 sub_1400F27F0();

__int64 __fastcall sub_1400F7020(__int64 *a1, __int64 a2, __int64 a3) {
    __int64 v4;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 v7;
    __int64 v2;
    __int64 v9;
    __int64 v10;
    __int64 v5;
    __int64 v6;
    __int64 v8;

    v4 = a3;
    ptr = (struct Struct_1_t *)a1;
    result = *a1;
    v7 = result;
    v7 -= ptr->field_10;
    if (a3 > v7) {
        v2 = a2;
        sub_140033EF0(ptr);
        if (result == 0) {
            result = ptr->field_0;
            if (v4 >= result) {
                ptr->field_18 = 1;
                v9 = ptr + 25;
                sub_140034180(v9, a2, v4);
                v10 = result;
                a2 = 0xFFFFFFFF00000003;
                a2 &= result;
                result = 0;
                v5 = 0x600000002;
                if (a2 != v5) result = v10;
                ptr->field_18 = 0;
            } else {
                v6 = ptr->field_10;
                v8 = ptr->field_8;
                v8 += v6;
                sub_1400F27F0(v8, v6, v4);
                v6 += v4;
                ptr->field_10 = v6;
                result = 0;
            }
        }
        return result;
    }
    return result;
}