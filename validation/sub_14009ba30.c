// inferred from 6 accesses on `a2`
struct Struct_1_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    char _pad_28[72];
    int field_78; // offset 120
    __int64 field_7C; // offset 124
    char _pad_7C[92];
    __int64 field_E0; // offset 224
};

// inferred from 5 accesses on `result`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[4];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

__int64 sub_140099E40();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_14009BA30(__int64 *a1,struct Struct_1_t *a2, int a3, int a4) {
    int v_48;
    int v_50;
    int v_58;
    int v_80;
    int v_88;
    int v_90;
    int v_98;
    int v_a0;
    int v_b0;
    __int64 v_d8;
    int v_f8;
    char *str;
    char *str2;
    int v3;
    __int64 v5;
    struct Struct_2_t *result;
    __int64 v6;
    __int64 v7;
    int v4;
    int v11;
    __int64 v2;
    __int64 v8;
    __int64 v9;
    __int64 v10;

    if (a2->field_E0 >= 6) {
        v3 = a2->field_78;
        v5 = a2->field_7C;
        result = (struct Struct_2_t *)v5;
        result = (struct Struct_2_t *)((__int64)(__int64)result | v3);
        if ((result == 0)) {
            *a1 = 0;
            *(a1 + 8) = 4;
            a1[2] = 0;
        } else {
            a4 += a3;
            if ((a4 >= 0)) {
                v_98 = v5;
                v_a0 = 0;
                v_b0 = 0;
                v_48 = 0;
                v_50 = 4;
                v_58 = 0;
                result = a2->field_20;
                v6 = a2->field_28;
                result -= 28;
                v7 = v6 + v6*8;
                v7 += v7*2;
                v7 += v6;
                while (v7 != 0) {
                    v4 = result->field_24;
                    v11 = result->field_28;
                    v6 = result->field_2C;
                    if (v6 > v4) v4 = v6;
                    v4 += v11;
                    if (!((v4 < 0))) {
                        result += 28;
                        v7 -= 28;
                        v2 = v3;
                        v2 -= v11;
                        if (v2 < v6) {
                            result = result->field_14;
                            v5 = v2;
                            v7 += (__int64)result;
                            v6 = a2->field_10;
                            if (v7 < v6) {
                                v_88 = v7;
                                result = (struct Struct_2_t *)v_98;
                                v8 = v_88;
                                v8 += (__int64)result;
                                result = (struct Struct_2_t *)v_88;
                                v_90 = v8;
                                if (v8 <= v6) JUMPOUT(0x14009bc19);
                            }
                        }
                    }
                }
                *(a1 + 8) = 9;
                result = 0x8000000000000000;
                *a1 = result;
                result = 0;
                a1 = 0;
                str2 = (char *)result;
                v_d8 = (__int64)result;
                v_f8 = (int)a1;
                v9 = off_140108030;
                v10 = off_140108038;
                sub_140099E40(str, str2, a3, a4);
                result = (struct Struct_2_t *)str;
                while (result != 0) {
                    a1 = (__int64 *)v_80;
                    a1 += (__int64)(__int64)a1*2;
                    result += (__int64)(__int64)a1*8;
                    result += 8;
                    v2 = result->field_8;
                    ((__int64 (*)())v9)(a1);
                    ((__int64 (*)())v10)(result, 0);
                }
            } else {
                *(a1 + 8) = 0;
                result = 0x8000000000000000;
                *a1 = result;
            }
        }
        return (__int64)result;
    }
    return (__int64)result;
}