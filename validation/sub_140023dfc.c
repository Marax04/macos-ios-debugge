// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3810();
__int64 sub_14001A580();
__int64 sub_140021AD5();
__int64 sub_140023EFB();
extern __int64 off_140110948;
extern __int64 off_14011D528;

__int64 __fastcall sub_140023DFC(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int arg_18;
    int arg_20;
    __int64 v_20;
    char *str;
    __int64 v11;
    __int64 *dst;
    __int64 *result;
    __int64 v5;
    __int64 i;
    __int64 v8;
    __int64 v4;
    __int64 v2;
    __int64 v9;
    __int64 v10;
    __int64 v6;

    v11 = rsp + 32;
    dst = (__int64 *)a2;
    result = a1;
    v5 = ((__int64 *)a2)[2];
    a1 = a2->field_0;
    a2 = a2->field_8;
    i = v5;
    while (i < a2) {
        v8 = *(a1 + i);
        ++i;
        *(dst + 16) = i;
        v4 = v8 - 48;
        v2 = (v4 < 10) ? 1 : 0;
        v4 = v8 - 97;
        v4 = (v4 < 6) ? 1 : 0;
        v4 |= v2;
        if (v8 != 95) {
            *(result + 8) = 0;
            *result = 0;
        } else {
            v9 = v6;
            v9 -= v5;
            if (!((v9 < 0))) {
                if (v5 != 0) {
                    if (*(a1 + v5) < 192) {
                        result = &off_140110948;
                        v_20 = (__int64)result;
                        sub_1400F3810(a1, a2, v5, i);
                        v11 = rsp + 128;
                        i = (__int64)a2;
                        v_20 = 1;
                        v10 = &off_14011D528;
                        v2 = v11 - 80;
                        sub_14001A580(v2, a1, i, v10);
                        do {
                            sub_140021AD5(str, v2);
                            result = (__int64 *)arg_18;
                        } while (result == 0);
                        if (result != 1) JUMPOUT(0x140023ef8);
                        a1 = (__int64 *)arg_20;
                        return sub_140023EFB();
                    }
                }
                a1 += v5;
                *result = a1;
                *(result + 8) = v9;
                return (__int64)a1;
            }
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return (__int64)result;
}