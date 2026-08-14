// inferred from 3 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[16];
    __int64 field_28; // offset 40
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 off_1401081C8();
__int64 off_140108060();
__int64 off_140108058();
__int64 off_140108030();
extern __int64 off_140108048;
extern __int64 off_140108038;

__int64 __fastcall sub_1400390D0(int *a1) {
    __int64 rsp;
    __int64 v_10;
    int v_18;
    int v_20;
    __int64 v_28;
    int v_4;
    __int64 *dst;
    struct Struct_2_t *ptr;
    __int64 v4;
    __int64 v8;
    __int64 v6;
    struct Struct_1_t *result;
    __int64 v9;
    struct Struct_3_t *ptr2;
    __int64 v3;

    dst = rsp + 80;
    *dst = -2;
    ptr = (struct Struct_2_t *)a1;
    if (*a1 != 1) {
        v4 = ptr->field_10;
        v8 = ptr->field_20;
    } else {
        v8 = ptr->field_20;
        off_1401081C8(v8);
        if (result == 0) {
            off_140108060();
        } else {
            v4 = ptr->field_10;
            v_4 = 0;
            v6 = dst - 4;
            off_140108058(v8, v4, v6, 1);
            if (result == 0) {
                off_140108060();
                if (result != 38) {
                    if (result != 109) {
                        result = ptr->field_18;
                        v9 = result->field_0;
                        ptr2 = result->field_8;
                        *(__int64 *)result = (__int64)(0);
                        result->field_8 = 1;
                        result->field_10 = 0;
                        sub_14002EDF0(8, 32);
                        if (result != 0) {
                            v4 = (__int64)result;
                            ptr->field_10 = result;
                            ptr2 = off_140108048;
                            ((__int64 (*)())ptr2)(v8);
                            a1 = ptr->field_28;
                            ((__int64 (*)())ptr2)(a1);
                            off_140108030();
                            a1 = (int *)result;
                            v3 = 0;
                            JUMPOUT(off_140108038);
                        }
                    } else {
                        result = 0;
                        *(__int64 *)ptr = (__int64)(0);
                        a1 = ptr->field_18;
                        a1[2] = a1[2] + result;
                        return (__int64)a1;
                    }
                    v_18 = v9;
                    v_10 = (__int64)ptr2;
                    v_20 = v8;
                    v_28 = (__int64)ptr;
                    sub_1400F3340(8, 32, v4);
                    v_10 = v3;
                    dst = v3 + 80;
                    if (v_18 != 0) {
                        off_140108030();
                        ((__int64 (*)())off_140108038)(result, 0, v_10);
                    }
                    v4 = off_140108048;
                    a1 = (int *)v_20;
                    ((__int64 (*)())v4)(a1);
                    ptr2 = (struct Struct_3_t *)v_28;
                    a1 = ptr2->field_28;
                    ((__int64 (*)())v4)(a1);
                    v4 = ptr2->field_10;
                    off_140108030();
                    return ((__int64 (*)())off_140108038)(result, 0, v4);
                }
                return v4;
            } else {
                result = (struct Struct_1_t *)v_4;
            }
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}