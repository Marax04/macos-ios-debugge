// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140038250();
__int64 sub_140032AB0();
__int64 sub_1400327E0();
extern __int64 off_1401161C0;

__int64 __fastcall sub_140038370(__int64 *a1) {
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 v3;
    __int64 v9;
    __int64 v7;
    __int64 v6;
    __int64 v11;
    __int64 v10;
    __int64 v2;
    __int64 v12;
    __int64 v8;
    __int64 *result;

    ptr = (struct Struct_1_t *)a1;
    v5 = *(a1 + 8);
    v3 = a1[2];
    sub_140038250(v5, v3);
    if (result != 0) {
        if (v3 == 2) {
            if (*result != 0x2E2E) {
                v9 = v3;
                while (v9 != 0) {
                    v7 = v9;
                    --v9;
                    if (v9 == 0) {
                        v6 = 0;
                        if (result != 0) v6 = result;
                        if (v6 != 0) {
                            if (result == 0) v3 = v7;
                            v6 += v3;
                            v6 -= v5;
                            sub_140032AB0(ptr, v6, v6, v3);
                            v11 = ptr->field_0;
                            v10 = ptr->field_10;
                            v2 = v11;
                            v2 -= v10;
                            if (v2 <= 3) JUMPOUT(0x140038471);
                            v12 = &off_1401161C0;
                            sub_1400327E0(ptr, v12, 1);
                            v8 = ptr->field_0;
                            v3 = ptr->field_10;
                            v8 -= v3;
                            if (v8 <= 2) JUMPOUT(0x1400384b3);
                            result = ptr->field_8;
                            *(result + v3 + 2) = 101;
                            *(result + v3) = 0x7865;
                            v3 += 3;
                            ptr->field_10 = v3;
                            ptr->field_18 = 0;
                        } else {
                        }
                        return v3;
                    } else {
                        v3 -= v7;
                        v6 = (__int64)result;
                        v6 += v7;
                        v3 = v9;
                        if (result != 0) v6 = result;
                        if (v6 != 0) {
                            return v3;
                        }
                        return v3;
                    }
                    return v3;
                }
                v6 = (__int64)result;
                result = 0;
                return (__int64)result;
            } else {
                v3 = 2;
                return v3;
            }
            return v3;
        }
        return v3;
    }
    return (__int64)result;
}