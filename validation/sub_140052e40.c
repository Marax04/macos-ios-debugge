// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

extern __int64 off_140121D8C;

__int64 __fastcall sub_140052E40(__int64 *a1, __int64 *a2) {
    struct Struct_1_t *ptr;
    int v7;
    __int64 *result;
    __int64 v3;
    __int64 i;
    __int64 v8;
    __int64 v4;
    __int64 v2;

    ptr = (struct Struct_1_t *)a2;
    a2 = *(a2 + 8);
    if (a2 == 0) {
        v7 = 9;
    } else {
        result = ptr->field_0;
        v3 = *result;
        i = v3 - 48;
        if (i >= 10) {
            i = 1;
            v7 = 8;
            v8 = v3 - 43;
            if (v8 <= 79) {
                v4 = &off_140121D8C;
                v8 = (__int64)a2;
                switch (v8) {
                    case 0:
                        v7 = 7;
                        if (i >= a2) {
                            return v7;
                        } else {
                            return v7;
                        }
                        return v7;
                    case 1:
                        return v7;
                    default:
                        v8 = (__int64)a2;
                        if (v3 == 32) {
                            v7 = 5;
                            if (i < a2) {
                                if (*(result + i) < 192) JUMPOUT(0x140052f46);
                                v8 = i;
                            } else {
                                v8 = (__int64)a2;
                                if ((0 /* unresolved: flags != */)) JUMPOUT(0x140052f46);
                            }
                        }
                        v2 = result + v8;
                        a2 -= v8;
                        break;
                }
                *(__int64 *)ptr = (__int64)(v2);
                ptr->field_8 = a2;
                *a1 = result;
                *(a1 + 8) = v8;
                a1[2] = v7;
                return (__int64)a2;
            }
            return (__int64)a2;
        } else {
            i = 0;
            v7 = *(result + i);
            v7 += 198;
            while (v7 >= 246) {
                ++i;
                i = (__int64)a2;
            }
            v7 = 0;
            if (i != 0) {
                return v7;
            } else {
                v8 = 0;
                v2 = (__int64)result;
            }
            return v2;
        }
        return v2;
    }
    return (__int64)result;
}