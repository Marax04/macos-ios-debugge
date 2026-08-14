// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14002DBBA();

__int64 __fastcall sub_14002DAE0(struct Struct_1_t *a1, size_t a2, size_t a3) {
    __int64 result;
    __int64 v3;
    __int64 *src;
    __int64 v5;
    int v2;

    a3 = ((__int64 *)a1)[7];
    if (a3 > 1) {
        result = 0;
        a2 = 0;
    } else {
        result = ((__int64 *)a1)[7];
        if (result == 0) {
            a2 = ((__int64 *)a1)[2];
            v3 = a2 - 5;
            if (v3 <= 1) {
                src = (a2 == 6) ? 1 : 0;
                v3 = a1->field_0;
                a2 = a1->field_8;
                v5 = (a3 != 0) ? 1 : 0;
                v5 |= (__int64)src;
                if ((v5 == 0)) {
                    src = 2;
                    if (a2 < 2) JUMPOUT(0x14002dc2b);
                } else {
                    src = 0;
                }
                v5 = 0;
                v2 = (src != a2) ? 1 : 0;
                if (src == a2) {
                    a2 = 0;
                    if (a3 == 0) JUMPOUT(0x14002dbba);
                } else {
                    src += v3;
                    v5 = v2;
                    v5 += (__int64)src;
                    a2 += v3;
                    a2 = (v5 == a2) ? 1 : 0;
                    v3 = *src;
                    src = (v3 != 46) ? 1 : 0;
                    src = (__int64 *)((__int64)(__int64)src | a2);
                    if ((src == 0)) JUMPOUT(0x14002dba1);
                    v3 = (v3 == 46) ? 1 : 0;
                    a2 &= v3;
                    if (a3 == 0) {
                        return sub_14002DBBA();
                    }
                }
                a1 = 0;
                result += (__int64)a1;
                result += a2;
                return result;
            }
        }
        return result;
    }
    return result;
}