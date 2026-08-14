// inferred from 2 accesses on `result`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 5 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400377D0(__int64 *a1, __int64 a2) {
    int v_10;
    __int64 v_18;
    int v_20;
    int v_28;
    int v_8;
    struct Struct_2_t *ptr;
    __int64 v4;
    __int64 v2;
    __int64 v10;
    __int64 *src;
    __int64 v5;
    __int64 v6;
    struct Struct_1_t *result;
    __int64 v9;

    v_8 = -2;
    ptr = *a1;
    *a1 = 0;
    if (ptr != 0) {
        v4 = off_140108030;
        v2 = off_140108038;
        *(__int64 *)ptr = (__int64)(ptr->field_0 - 1);
        while (!((ptr->field_0 != 0))) {
            v10 = ptr->field_10;
            src = ptr->field_18;
            v5 = ptr->field_20;
            if (ptr == -1) {
                if (v10 != 0) {
                    v_10 = v10;
                    v_20 = v5;
                    v_28 = v5;
                    v_18 = (__int64)src;
                    v6 = *src;
                    if (v6 == 0) {
                        result = (struct Struct_1_t *)v_18;
                        v9 = v_20;
                        if (result->field_8 == 0) {
                            ptr = (struct Struct_2_t *)v9;
                            return (__int64)ptr;
                        }
                        if (result->field_10 >= 17) {
                            ptr = (struct Struct_2_t *)v_10;
                            ptr = *(__int64 *)(ptr - 8);
                            ((__int64 (*)())v4)();
                            ((__int64 (*)())v2)(result, 0, ptr);
                            return (__int64)ptr;
                        }
                        ptr = (struct Struct_2_t *)v_10;
                        return (__int64)ptr;
                    }
                    ((__int64 (*)())v6)(v_10);
                    return (__int64)ptr;
                }
                return (__int64)ptr;
            }
            ptr->field_8 = ptr->field_8 - 1;
            if ((ptr->field_8 != 0)) {
                return (__int64)ptr;
            }
            ((__int64 (*)())v4)();
            ((__int64 (*)())v2)(result, 0, ptr);
            return (__int64)ptr;
        }
    }
    return (__int64)result;
}