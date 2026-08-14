// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[20];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

__int64 sub_14002EDF0();
__int64 sub_1400986BC();

__int64 __fastcall sub_140098370(__int64 *a1, __int64 *a2) {
    int v_20;
    int v_28;
    int v_30;
    __int64 v_38;
    int v_44;
    int v_60;
    __int64 result;
    __int64 v11;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 v6;
    int v8;
    __int64 v4;
    __int64 v3;
    __int64 v12;
    __int64 *src;
    __int64 v2;
    int v13;
    __int64 v10;

    if (a2[28] >= 6) {
        result = a2[15];
        v11 = a2[15];
        ptr = (struct Struct_1_t *)v11;
        ptr = (struct Struct_1_t *)((__int64)(__int64)ptr | result);
        if ((ptr == 0)) {
            *a1 = 0;
            *(a1 + 8) = 8;
            a1[2] = 0;
        } else {
            ptr = a2[4];
            v7 = a2[5];
            ptr -= 28;
            v6 = v7 + v7*8;
            v6 += v6*2;
            v6 += v7;
            while (v6 != 0) {
                v8 = ptr->field_24;
                v4 = ptr->field_28;
                v7 = ptr->field_2C;
                if (v7 > v8) v8 = v7;
                v8 += v4;
                if (!((v8 < 0))) {
                    ptr += 28;
                    v6 -= 28;
                    v3 = result;
                    v3 -= v4;
                    if (v3 < v7) {
                        ptr = ptr->field_14;
                        result = v3;
                        result += (__int64)ptr;
                        v12 = a2[2];
                        if (result < v12) {
                            v11 += result;
                            if (v11 <= v12) {
                                v_20 = 0;
                                v_28 = 8;
                                v_30 = 0;
                                src = *(a2 + 8);
                                v2 = 8;
                                v13 = 0;
                                a2 = 0x7FFFFFFFFFFFFFFF;
                                v4 = result + 8;
                                if (v4 > v11) JUMPOUT(0x140098632);
                                v10 = *(src + result + 4);
                                if (v10 < 8) JUMPOUT(0x140098648);
                                ptr = result + v10;
                                if (ptr > v11) JUMPOUT(0x140098648);
                                v10 -= 8;
                                v3 = v10;
                                v3 >>= 1;
                                v2 =  + v3*4;
                                if (v2 >= a2) JUMPOUT(0x1400985ec);
                                result = *(src + result);
                                v_44 = result;
                                v_38 = (__int64)ptr;
                                if (v2 == 0) JUMPOUT(0x1400984f8);
                                v_60 = (int)a1;
                                sub_14002EDF0(0, v2, ptr, v6);
                                ptr = (struct Struct_1_t *)v_38;
                                a1 = (__int64 *)v_60;
                                a2 = (__int64 *)v3;
                                if (result != 0) JUMPOUT(0x1400984ff);
                                return sub_1400986BC();
                            }
                        }
                    }
                }
            }
            *(a1 + 8) = 9;
            result = 0x8000000000000000;
            *a1 = result;
        }
        return result;
    }
    return result;
}