// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    char field_4; // offset 4
    char field_5; // offset 5
    __int64 field_6; // offset 6
};

__int64 sub_140038A70();
__int64 sub_1400F6820();
__int64 sub_1400F3B80();
__int64 sub_1400F6B50();
__int64 off_140108258();
extern __int64 off_14012D268;
extern __int64 off_140108260;
extern __int64 off_140108060;
extern __int64 off_1401102B8;
extern __int64 off_14011D418;
extern __int64 off_1401106F0;
extern __int64 off_1401102A0;

__int64 __fastcall sub_140020C60(__int64 *a1) {
    int v_20;
    int v_30;
    char *str;
    struct Struct_1_t *ptr;
    __int64 src;
    __int64 result;
    __int64 v2;
    __int64 v9;
    int v12;
    __int64 v10;
    int v11;
    __int64 v7;
    __int64 v8;
    __int64 v6;
    __int64 v3;

    sub_140038A70();
    ptr = (struct Struct_1_t *)a1;
    src = a1 + 4;
    a1 = 1;
    result = 0;
    /* cmpxchg %(__int64)a1, 4(%(__int64)ptr) */;
    if (!((0 /* unresolved: flags != */))) {
        v2 = off_14012D268;
        v2 <<= 1;
        if (v2 != 0) {
            sub_1400F6820();
            v2 = result;
            v2 ^= 1;
            result = ptr->field_5;
            if (result == 0) {
                v9 = off_140108260;
                v12 = 1;
                v10 = off_140108060;
                while (ptr->field_6 == 0) {
                    v11 = ptr->field_0;
                    result = 0;
                    { __int64 __xchg_tmp = ptr->field_4; ptr->field_4 = result; result = __xchg_tmp; };
                    if (result == 2) {
                        off_140108258(src);
                    }
                    str = (char *)v11;
                    ((__int64 (*)())v9)(ptr, v3, 4, 0xFFFFFFFF);
                    if (result != 1) {
                        ((__int64 (*)())v10)(0);
                        result = 0;
                        /* cmpxchg %v12, (%src) */;
                        if ((0 /* unresolved: flags == */)) {
                            result = ptr->field_5;
                            str = (char *)src;
                            v_30 = v2;
                            v7 = &off_1401102B8;
                            v_20 = v7;
                            v8 = &off_14011D418;
                            v6 = &off_1401106F0;
                            sub_1400F3B80(v8, 43, str, v6);
                        }
                        sub_1400F6B50(src);
                        result = ptr->field_5;
                        return result;
                    }
                    /* cmpxchg %v12, (%src) */;
                    if ((0 /* unresolved: flags != */)) {
                        return result;
                    }
                    return result;
                }
                ptr->field_6 = 0;
                if (v2 == 0) {
                    v2 = off_14012D268;
                    v2 <<= 1;
                    if (v2 != 0) JUMPOUT(0x140020e10);
                }
                result = 0;
                result = _InterlockedExchange64(src, result);
                if (result == 2) JUMPOUT(0x140020df6);
                return result;
            }
            str = (char *)src;
            v_30 = v2;
            v7 = &off_1401102A0;
            return v7;
        }
        v2 = 0;
        result = ptr->field_5;
        if (result != 0) {
            return result;
        }
        return result;
    }
    do {
        sub_1400F6B50(src);
        v2 = off_14012D268;
        v2 <<= 1;
        return result;
    } while (true);
}