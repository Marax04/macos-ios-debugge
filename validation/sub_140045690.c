// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140045690(struct Struct_1_t *a1, __int64 a2, __int64 a3) {
    __int64 result;
    __int64 v3;
    __int64 v4;
    __int64 v2;

    a2 = a1->field_0;
    result = a2;
    result = -result;
    if (!((0 /* overflow check on (-result) */))) {
        if (!((0 /* unresolved: flags >= */))) {
            result = 8;
            if (a2 == a3) {
                if (a1->field_8 != 0) {
                    v3 = *(__int64 *)(a1 + result);
                    off_140108030(16, a1, a2, 0x8000000000000001);
                    v4 = result;
                    a2 = 0;
                    v2 = v3;
                    JUMPOUT(off_140108038);
                }
                return v2;
            }
            return v2;
        }
    }
    return result;
}