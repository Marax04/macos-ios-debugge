// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 4 accesses on `result`
struct Struct_2_t {
    int field_0; // offset 0
    char _pad_0[3];
    char field_7; // offset 7
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140033EF0();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140034D00(struct Struct_1_t *a1, __int64 a2) {
    int v_10;
    __int64 v_18;
    int v_20;
    int v_28;
    int v_8;
    __int64 v3;
    __int64 v2;
    __int64 v6;
    __int64 v7;
    struct Struct_2_t *result;
    __int64 *src;
    __int64 *v9;

    v_8 = -2;
    if (((__int64 *)a1)[3] == 0) {
        v_10 = (int)a1;
        sub_140033EF0();
        a1 = (struct Struct_1_t *)result;
        a1 = (struct Struct_1_t *)((__int64)(__int64)a1 & 3);
        a1 = (struct Struct_1_t *)v_10;
        if (!((a1 == 1))) {
            if (a1->field_0 != 0) {
                do {
                    v3 = a1->field_8;
                    off_140108030(a1);
                    v2 = (__int64)result;
                    JUMPOUT(off_140108038);
                    v6 = (__int64)result;
                    --v6;
                    v_28 = v6;
                    v7 = *(__int64 *)(result - 1);
                    v_20 = v7;
                    result = result->field_7;
                    v_18 = (__int64)result;
                    result = result->field_0;
                    if (result == 0) {
                        src = (__int64 *)v_20;
                        result = (struct Struct_2_t *)v_18;
                        v9 = (__int64 *)v_10;
                        if (result->field_8 == 0) {
                            off_140108030();
                            ((__int64 (*)())off_140108038)(result, 0, v_28);
                            a1 = (struct Struct_1_t *)v9;
                            return (__int64)a1;
                        }
                        if (result->field_10 < 17) {
                            off_140108030();
                            ((__int64 (*)())off_140108038)(result, 0, src);
                            return (__int64)a1;
                        }
                        src = *(src - 8);
                        return (__int64)src;
                    }
                    ((__int64 (*)())result)(v_20, 0, v3);
                    return (__int64)src;
                } while (*v9 != 0);
            }
            return (__int64)src;
        }
        return (__int64)src;
    }
    return (__int64)result;
}