// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
};

__int64 sub_140023492();
__int64 sub_140013110();
extern __int64 off_140116F20;

__int64 __fastcall sub_1400244CB(size_t *a1) {
    __int64 v6;
    __int64 i;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v9;
    __int64 v7;
    __int64 result;
    __int64 v3;
    __int64 v8;

    v6 = *a1;
    if (v6 == 0) {
        i = 0;
    } else {
        ptr = (struct Struct_1_t *)a1;
        v5 = 0;
        v9 = &off_140116F20;
        i = 0;
        do {
            v7 = ptr->field_10;
            if (i == 0) {
                sub_140023492(ptr, 1);
                if (result == 0) {
                    ++i;
                    v6 = ptr->field_0;
                    result = v5;
                    v3 = i;
                    return v3;
                }
                v5 = 1;
                return v5;
            }
            v8 = ptr->field_20;
            if (v8 == 0) {
                return v8;
            }
            sub_140013110(v8, v9, 2);
            if (result == 0) {
                return v8;
            }
            return v8;
        } while (v6 != 0);
        return v8;
    }
    v5 = 0;
    return result;
}