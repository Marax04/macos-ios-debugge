// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14009E170(__int64 *a1, __int64 a2) {
    __int64 v_20;
    int v_28;
    __int64 v_30;
    __int64 *result;
    __int64 i;
    __int64 v7;
    __int64 v9;
    struct Struct_1_t *ptr;
    __int64 v2;
    __int64 v8;
    __int64 v5;
    __int64 *src;

    result = *(a1 + 8);
    v_20 = (__int64)result;
    v_28 = (int)a1;
    result = a1[2];
    v_30 = (__int64)result;
    if (result != 0) {
        i = 0;
        v7 = off_140108030;
        v9 = off_140108038;
        do {
            result = i + i*2;
            result = (__int64 *)((__int64)(__int64)result << 4);
            a1 = (__int64 *)v_20;
            ptr = (__int64)a1 + (__int64)result;
            v2 = ptr->field_20;
            v8 = ptr->field_28;
            if (v8 == 0) {
                if (ptr->field_18 == 0) {
                    ++i;
                    result = (__int64 *)v_28;
                    if (*result != 0) {
                        ((__int64 (*)())off_140108030)();
                        a1 = result;
                        a2 = 0;
                        v5 = v_20;
                        JUMPOUT(off_140108038);
                    }
                    return v5;
                }
                ((__int64 (*)())v7)();
                ((__int64 (*)())v9)(result, 0, v2);
                return v5;
            }
            src = v2 + 8;
            do {
                result = *(src - 8);
                result = (__int64 *)((__int64)(__int64)result << 1);
                src += 40;
                --v8;
            } while (!((v8 == 0)));
            return v8;
        } while (i != v_30);
    }
    return (__int64)result;
}