// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400E426B();
__int64 sub_1400D5BD0();
__int64 sub_1400F2D20();
__int64 sub_1400F27F0();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400E4040(int *a1, int *a2, size_t a3) {
    __int64 rsp;
    int arg_8;
    int v_20;
    int v_30;
    __int64 v_38;
    int v_40;
    __int64 v4;
    __int64 v2;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 *result;
    __int64 v6;
    __int64 v7;
    __int64 v9;
    __int64 v8;
    __int64 v10;
    __int64 *dst;

    v4 = a3;
    v2 = (__int64)a2;
    ptr = (struct Struct_1_t *)a1;
    sub_14002EDF0(0, 8);
    if (result == 0) {
        sub_1400F3326(1, 8);
        ptr = (struct Struct_1_t *)a2;
        v5 = *a1;
        v4 = a1[2];
        result = (__int64 *)v5;
        result -= v4;
        a2 = 0xC6FF49371CB60F43;
        v6 = 0xC6FF493704B60F43;
        if (a3 != 0) v6 = a2;
        if (result <= 7) JUMPOUT(0x1400e427e);
        result = (__int64 *)arg_8;
        *(result + v4) = v6;
        a2 = v4 + 8;
        a1[2] = a2;
        v5 -= (__int64)a2;
        if (v5 <= 2) JUMPOUT(0x1400e42b3);
        *(__int64 *)((__int64)result + (__int64)a2 + 2) = 45;
        *(__int64 *)((__int64)result + (__int64)a2) = 0x8D48;
        a2 += 3;
        a1[2] = a2;
        if (ptr < 0) JUMPOUT(0x1400e4373);
        v4 += 15;
        if ((v4 < 0)) JUMPOUT(0x1400e4373);
        ptr -= v4;
        v7 = (__int64)ptr;
        if (ptr != ptr) JUMPOUT(0x1400e439c);
        v9 = *a1;
        v9 -= (__int64)a2;
        if (v9 <= 3) JUMPOUT(0x1400e42e6);
        *(__int64 *)((__int64)result + (__int64)a2) = ptr;
        a2 += 4;
        a1[2] = a2;
        if (a3 == 0) JUMPOUT(0x1400e424f);
        a3 = *a1;
        a3 -= (__int64)a2;
        if (a3 <= 4) JUMPOUT(0x1400e4319);
        *(__int64 *)((__int64)result + (__int64)a2 + 4) = 0;
        *(__int64 *)((__int64)result + (__int64)a2) = 0x1D5CB60F;
        return sub_1400E426B();
    } else {
        v_30 = 8;
        v_38 = (__int64)result;
        *result = 0x894A;
        v_40 = 2;
        v_20 = v4;
        a1 = rsp + 48;
        sub_1400D5BD0(a1, v2, 5, 3);
        v8 = v_30;
        v2 = v_38;
        v10 = v_40;
        result = ptr->field_0;
        v4 = ptr->field_10;
        result -= v4;
        if (v10 > result) {
            v_20 = 1;
            sub_1400F2D20(ptr, v4, v10, 1);
            v4 = ptr->field_10;
        }
        dst = ptr->field_8;
        a1 = dst + v4;
        sub_1400F27F0(a1, v2, v10);
        v4 += v10;
        ptr->field_10 = v4;
        if (v8 != 0) {
            off_140108030();
            off_140108038(result, 0, v2);
        }
        result = ptr->field_0;
        result -= v4;
        if (result <= 2) {
            v_20 = 1;
            sub_1400F2D20(ptr, v4, 3, 1);
            dst = ptr->field_8;
            v4 = ptr->field_10;
        }
        *(dst + v4 + 2) = 197;
        *(dst + v4) = 0xFF49;
        v4 += 3;
        ptr->field_10 = v4;
        return (__int64)result;
    }
}