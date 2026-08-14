// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

extern __int64 off_140121FF0;
extern __int64 off_140122000;

__int64 __fastcall sub_1400583C0(__int64 a1,struct Struct_1_t *a2) {
    __int64 v5;
    __int64 v6;
    __int64 result;
    __int64 v4;
    __int64 v7;
    __int64 v8;
    __int64 v2;
    __int64 v3;

    v5 = a2->field_0;
    v6 = v5 - 8;
    result = 1;
    if (v5 >= 8) result = v6;
    v4 = &off_140121FF0;
    switch (result) {
        case 0:
            return v4;
        default:
            v7 = v5 - 2;
            v6 = 6;
            if (v5 >= 2) v4 = v7;
            v8 = &off_140122000;
            if (v4) {
                result = a2->field_8;
                v2 = 0x8000000000000003;
                if (result != v2) {
                    v5 = 0x8000000000000002;
                    if (result >= v5) {
                        return v5;
                    } else {
                    }
                }
            } else {
                result = ((__int64 *)a2)[4];
                v3 = 0x8000000000000003;
                if (result != v3) {
                    v5 = 0x8000000000000002;
                    if (result >= v5) {
                        result = 48;
                        v5 = 40;
                        return v5;
                    }
                }
            }
            return result;
    }
}