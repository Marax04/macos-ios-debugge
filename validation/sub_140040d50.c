// inferred from 5 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140041640();
__int64 off_140108030();
__int64 off_140108258();
extern __int64 off_140108038;

__int64 __fastcall sub_140040D50(__int64 *a1, __int64 a2) {
    int v_10;
    __int64 v_18;
    __int64 v_20;
    __int64 v_28;
    struct Struct_2_t *ptr;
    __int64 *src;
    __int64 v2;
    __int64 *src2;
    struct Struct_3_t *ptr2;
    __int64 *src3;
    struct Struct_1_t *result;
    __int64 *src4;
    __int64 v5;

    v_10 = -2;
    ptr = (struct Struct_2_t *)a1;
    src = *(a1 + 8);
    v2 = a1[2];
    v2 = (v2 != 0) ? 1 : 0;
    if (src != 0) {
        if (v2 != 0) {
            v_20 = v2;
            v_18 = (__int64)ptr;
            src2 = ptr->field_18;
            v_28 = (__int64)src2;
            src2 = *src2;
            if (src2 != 0) {
                a1 = (__int64 *)v_20;
                ((__int64 (*)())src2)(a1);
            }
            ptr2 = (struct Struct_3_t *)v_28;
            ptr = (struct Struct_2_t *)v_18;
            src3 = (__int64 *)v_20;
            if (ptr2->field_8 != 0) {
                if (ptr2->field_10 >= 17) {
                    src3 = *(src3 - 8);
                }
                off_140108030();
                ((__int64 (*)())off_140108038)(ptr2, 0, src3);
            }
        }
    }
    ptr->field_8 = 0;
    result = ptr->field_0;
    if (result != 0) {
        src = (__int64 *)((__int64)(__int64)src & v2);
        if (!((src == 0))) {
            result->field_20 = 1;
        }
        result->field_18 = result->field_18 - 1;
        if (!((result->field_18 != 0))) {
            a1 = result->field_10;
            result = 1;
            result = _InterlockedExchange64(&a1[5], result);
            if (result == 255) {
                a1 += 40;
                off_140108258(a1);
            }
        }
        result = ptr->field_0;
        if (result != 0) {
            *(__int64 *)result = (__int64)(result->field_0 - 1);
            if (!((result->field_0 != 0))) {
                a1 = ptr->field_0;
                sub_140041640(a1);
            }
        }
        if (ptr->field_8 != 0) {
            result = ptr->field_10;
            if (result != 0) {
                v_20 = (__int64)result;
                src4 = ptr->field_18;
                v_18 = (__int64)src4;
                src4 = *src4;
                if (src4 != 0) {
                    a1 = (__int64 *)v_20;
                    ((__int64 (*)())src4)(a1);
                }
                result = (struct Struct_1_t *)v_18;
                src = (__int64 *)v_20;
                if (result->field_8 != 0) {
                    if (result->field_10 >= 17) {
                        src = *(src - 8);
                    }
                    off_140108030();
                    a1 = (__int64 *)result;
                    a2 = 0;
                    v5 = (__int64)src;
                    JUMPOUT(off_140108038);
                }
            }
        }
    }
    return (__int64)result;
}