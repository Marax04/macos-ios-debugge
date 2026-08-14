// inferred from 4 accesses on `result`
struct Struct_1_t {
    char _pad_start[20];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

// inferred from 4 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[20];
    __int64 field_14; // offset 20
    char _pad_14[8];
    int field_24; // offset 36
    int field_28; // offset 40
    __int64 field_2C; // offset 44
};

__int64 sub_1400F3600();
__int64 sub_14009B9BD();
extern __int64 off_140119550;

__int64 __fastcall sub_14009B5C0(int *a1, size_t *a2, int a3) {
    __int64 rsp;
    int v_50;
    int v_60;
    int v_68;
    int v_70;
    struct Struct_1_t *result;
    __int64 v5;
    __int64 *v6;
    __int64 v7;
    __int64 v3;
    struct Struct_2_t *ptr;
    __int64 v10;
    __int64 v2;
    __int64 i;
    __int64 v12;
    __int64 v11;
    __int64 *src;

    if (a2 < a1[5]) {
        result = a1[2];
        v5 = a1[8];
        v6 = a2 + (__int64)(__int64)a2*4;
        v7 = v5 + (__int64)(__int64)v6*8;
        v7 += 36;
        v6 = v5 + (__int64)(__int64)v6*8;
        v6 += 40;
        if (v6 >= v7) {
            if (v6 <= result) {
                result = *(a1 + 8);
                *(__int64 *)(result + v7) = (__int64)(a3);
                result = a1[4];
                a1 = a2 + (__int64)(__int64)a2*8;
                a1 += (__int64)(__int64)a1*2;
                a1 = (int *)((__int64)a1 + (__int64)a2);
                *(__int64 *)((__int64)result + (__int64)a1 + 24) = a3;
                return (__int64)a1;
            }
        }
        v5 = &off_140119550;
        sub_1400F3600(v7, v6, a3, v5);
        if (*(v6 + 224) < 10) JUMPOUT(0x14009b804);
        v3 = a2[19];
        result = a2[19];
        result = (struct Struct_1_t *)((__int64)(__int64)result | v3);
        if ((result == 0)) JUMPOUT(0x14009b804);
        result = a2[4];
        v7 = a2[5];
        ptr = result - 28;
        v10 = v7 + v7*8;
        v10 += v10*2;
        v2 = v10 + v7;
        do {
            if (v2 == 0) JUMPOUT(0x14009b80a);
            v10 = ptr->field_24;
            i = ptr->field_28;
            v12 = ptr->field_2C;
            if (v12 > v10) v10 = v12;
            v10 += i;
            if ((v10 < 0)) JUMPOUT(0x14009b80a);
            ptr += 28;
            v2 -= 28;
            v11 = v3;
            v11 -= i;
        } while (v3 >= v10);
        if (v11 >= v12) JUMPOUT(0x14009b80a);
        ptr = ptr->field_14;
        v3 = v11;
        v3 += (__int64)ptr;
        v2 = a2[2];
        if (v3 >= v2) JUMPOUT(0x14009b80a);
        ptr = v3 + 40;
        if (v2 < ptr) JUMPOUT(0x14009b80a);
        src = *(a2 + 8);
        v11 = *(src + v3 + 24);
        v_60 = 0;
        v_68 = 8;
        v_70 = 0;
        ptr = a2[9];
        v_50 = v5;
        if (v11 == 0) JUMPOUT(0x14009b821);
        v5 = 0;
        v11 -= (__int64)ptr;
        if (v11 >= 0) v5 = v11;
        v11 = 0xFFFFFFFF;
        if (v5 >= v11) v5 = v11;
        result -= 28;
        v10 += v7;
        do {
            if (v10 == 0) JUMPOUT(0x14009b821);
            v12 = result->field_24;
            i = result->field_28;
            v7 = result->field_2C;
            if (v7 > v12) v12 = v7;
            v12 += i;
            if ((v12 < 0)) JUMPOUT(0x14009b821);
            result += 28;
            v10 -= 28;
            v11 = v5;
            v11 -= i;
        } while (v12 <= v5);
        if (v11 >= v7) JUMPOUT(0x14009b821);
        result = result->field_14;
        v12 = v11;
        v12 += (__int64)result;
        if (v12 >= v2) JUMPOUT(0x14009b821);
        src += v12;
        v12 += 8;
        result = 8;
        i = 0;
        v5 = rsp + 96;
        do {
            if (v2 < v12) JUMPOUT(0x14009b9a7);
            v11 = src[i];
            if (v11 == 0) JUMPOUT(0x14009b9a7);
            if (i == v_60) JUMPOUT(0x14009b7dd);
            ((__int64 *)result)[i] = (__int64)(v11);
            ++i;
            v_70 = i;
            v12 += 8;
        } while (i != 64);
        return sub_14009B9BD();
    }
    return (__int64)result;
}