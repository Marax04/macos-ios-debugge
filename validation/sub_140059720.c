// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_1400599D0();
__int64 sub_140059981();

__int64 __fastcall sub_140059720(size_t a1,struct Struct_1_t *a2,struct Struct_2_t *a3) {
    int v_26;
    int v_27;
    __int64 v3;
    __int64 *src;
    __int64 v2;
    __int64 v9;
    __int64 result;
    __int64 i;
    __int64 v6;
    __int64 v7;
    int v12;
    __int64 v10;
    __int64 v11;
    __int64 v8;

    v3 = a1;
    src = a3->field_10;
    v2 = a3->field_18;
    v9 = ((__int64 *)a2)[2];
    result = a2->field_0;
    i = a2->field_8;
    if (v9 == 0) {
        if (result == 0) {
            if (v2 == 0) JUMPOUT(0x140059974);
            result = ((__int64 *)a2)[3];
            a1 = ((__int64 *)a2)[3];
            v6 = ((__int64 *)a2)[4];
            v7 = ((__int64 *)a2)[3];
            v12 = ((__int64 *)a2)[3];
            v10 = ((__int64 *)a2)[3];
            v11 = ((__int64 *)a2)[3];
            v8 = ((__int64 *)a2)[4];
            a2 = ((__int64 *)a2)[4];
            i = 0;
            do {
                v9 = *(src + i);
                ++i;
                if (v2 == i) JUMPOUT(0x14005996f);
            } while (true);
        }
    } else {
        if (v9 != 1) {
            v7 = -1;
            if (result == 0) i = v7;
        } else {
            if (result == 0) {
                a1 = 1;
                if (v2 != 0) {
                    result = ((__int64 *)a2)[3];
                    v6 = ((__int64 *)a2)[3];
                    v7 = ((__int64 *)a2)[4];
                    v12 = ((__int64 *)a2)[3];
                    v10 = ((__int64 *)a2)[3];
                    v11 = ((__int64 *)a2)[3];
                    v8 = ((__int64 *)a2)[3];
                    i = ((__int64 *)a2)[4];
                    v_26 = i;
                    a2 = ((__int64 *)a2)[4];
                    i = 0;
                    do {
                        v9 = *(src + i);
                        ++i;
                    } while (v2 != i);
                    i = v2;
                    if (i != 0) JUMPOUT(0x140059977);
                }
                result = 0;
                return sub_1400599D0();
            }
        }
    }
    if (i >= v9) {
        if (v2 != 0) {
            result = ((__int64 *)a2)[3];
            v6 = ((__int64 *)a2)[3];
            v7 = ((__int64 *)a2)[4];
            v12 = ((__int64 *)a2)[3];
            v10 = ((__int64 *)a2)[3];
            v11 = ((__int64 *)a2)[3];
            v8 = ((__int64 *)a2)[3];
            v9 = ((__int64 *)a2)[4];
            v_26 = v9;
            a2 = ((__int64 *)a2)[4];
            v_27 = (int)a2;
            a2 = 0;
            do {
                v9 = *(__int64 *)((__int64)src + (__int64)a2);
                if (i != a2) {
                    ++a2;
                    result = 0;
                    if (v9 > v2) JUMPOUT(0x1400599cb);
                    v10 = src + v2;
                    v6 = v2;
                    return sub_140059981();
                }
                v8 = v2;
                v8 -= i;
                if ((v8 < 0)) JUMPOUT(0x140059a5c);
                v11 = src + i;
                return sub_140059981();
            } while (v2 != a2);
        }
        return result;
    } else {
        a1 = 2;
        result = 0;
        return sub_1400599D0();
    }
}