// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

extern __int64 off_14010B442;

__int64 __fastcall sub_1400138C0(struct Struct_1_t *a1, int a2, size_t *a3) {
    int v_8;
    struct Struct_2_t *ptr;
    __int64 *src;
    __int64 v4;
    __int64 result;
    __int64 v6;
    __int64 v7;
    __int64 v8;
    __int64 v5;

    ptr = (struct Struct_2_t *)a3;
    src = (__int64 *)a2;
    v4 = (__int64)a1;
    a3 = *(a3 + 8);
    if (a3 != 0) {
        a2 = ptr->field_0;
        a1 = (struct Struct_1_t *)v4;
        ((__int64 (*)())(*(src + 24)))();
        a1 = (struct Struct_1_t *)result;
        result = 1;
        if (a1 == 0) {
            result = ptr->field_18;
            if (result != 0) {
                v6 = ptr->field_10;
                result += result*2;
                v7 = v6 + result*8;
                result = v6 + 24;
                ptr = &off_14010B442;
                v_8 = v7;
                do {
                    a1 = (struct Struct_1_t *)v6;
                    v6 = result;
                    result = a1->field_0;
                    v8 = a1->field_8;
                    if (v8 < 65) {
                        if (v8 == 0) {
                            result = v6 + 24;
                            if (v6 == v7) result = v6;
                            result = 0;
                            return result;
                        }
                        v5 = *(src + 24);
                        ((__int64 (*)())v5)(v4, ptr, v8);
                        v7 = v_8;
                        if (result == 0) {
                            return v7;
                        }
                        result = 1;
                        return result;
                    }
                    v5 = *(src + 24);
                    ((__int64 (*)())v5)(v4, ptr, 64);
                    while (result == 0) {
                        v8 -= 64;
                        return v8;
                    }
                    return v8;
                } while (v6 != v7);
            }
            return v8;
        }
        return v8;
    }
    return result;
}