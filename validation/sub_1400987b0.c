// inferred from 4 accesses on `a2`
struct Struct_1_t {
    char _pad_start[20];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

__int64 sub_1400F3600();
__int64 sub_140098996();
extern __int64 off_1401192C0;
extern __int64 off_1401192A8;

__int64 __fastcall sub_1400987B0(int *a1,struct Struct_1_t *a2, int a3) {
    __int64 rsp;
    int arg_10;
    int arg_20;
    int arg_28;
    int arg_78;
    int arg_7c;
    int v_100;
    int v_b0;
    int v_c0;
    int v_c8;
    __int64 result;
    __int64 v6;
    __int64 v3;
    __int64 v7;
    __int64 v5;
    __int64 v2;
    __int64 v4;
    __int64 v9;
    __int64 v8;

    result = a3;
    v6 = (__int64)a2;
    a1[15] = a2;
    a1[15] = a3;
    a3 = a1[2];
    a2 = a1[7];
    v3 = a2 + 160;
    if (v3 <= a3) {
        v7 = a2 + 152;
        a2 += 156;
        if (v7 <= -5) {
            if (a2 > a3) {
                v5 = &off_1401192C0;
                sub_1400F3600(v7, a2, a3, v5);
            } else {
                a1 = *(a1 + 8);
                *(a1 + v7) = v6;
                if (v3 >= a2) {
                    *(__int64 *)((__int64)a1 + (__int64)a2) = result;
                    return (__int64)a1;
                }
            }
            v5 = &off_1401192A8;
            sub_1400F3600(a2, v3, a3, v5);
            v_100 = v5;
            v2 = v3;
            v4 = (__int64)a1;
            v_b0 = 0;
            v_c0 = 0;
            if (a1[28] >= 6) {
                a1 = (int *)arg_78;
                result = arg_7c;
                a2 = (struct Struct_1_t *)result;
                a2 = (struct Struct_1_t *)((__int64)(__int64)a2 | (__int64)a1);
                if (!((a2 == 0))) {
                    a2 = (struct Struct_1_t *)arg_20;
                    v5 = arg_28;
                    a2 -= 28;
                    v6 = v5 + v5*8;
                    v9 = v6 + v6*2;
                    v9 += v5;
                    do {
                        if (v9 == 0) JUMPOUT(0x140098ebe);
                        v6 = a2->field_24;
                        v3 = a2->field_28;
                        v5 = a2->field_2C;
                        if (v5 > v6) v6 = v5;
                        v6 += v3;
                        if ((v6 < 0)) JUMPOUT(0x140098ebe);
                        a2 += 28;
                        v9 -= 28;
                        v7 = (__int64)a1;
                        v7 -= v3;
                    } while ((v7 < 0));
                    if (v7 >= v5) JUMPOUT(0x140098ebe);
                    a1 = a2->field_14;
                    a2 = (struct Struct_1_t *)v7;
                    a2 = (struct Struct_1_t *)((__int64)a2 + (__int64)a1);
                    v8 = arg_10;
                    if (a2 >= v8) JUMPOUT(0x140098ebe);
                    if (result >= 8) JUMPOUT(0x140098f70);
                }
            }
            v_c8 = v4;
            if (a3 == 0) JUMPOUT(0x140098a94);
            v3 = v2 + a3*4;
            result = v2 + 4;
            v4 = rsp + 176;
            return sub_140098996();
        }
        return v4;
    }
    return result;
}