// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    __int64 field_4; // offset 4
};

__int64 sub_1400A7C48();
__int64 sub_14002EDF0();
__int64 sub_14006EC70();
__int64 sub_1400A7CAF();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400A793C(__int64 *a1, int a2, size_t a3, int a4) {
    __int64 rsp;
    int v_138;
    __int64 v_258;
    int v_300;
    int v_308;
    int v_310;
    int v_350;
    int v_358;
    int v_360;
    int v_368;
    int v_370;
    int v_548;
    int v_550;
    int v_560;
    int v_568;
    int v_578;
    int v_590;
    int v_5f0;
    __int64 v_5f8;
    int v_600;
    int v_608;
    int v_610;
    int v_618;
    int v_628;
    int v_630;
    int v_640;
    int v_648;
    int v_650;
    __int64 v_80;
    __int64 v_a70;
    __int64 v_b8;
    int v_d0;
    int v_f0;
    char *str;
    __int64 v8;
    __int64 v10;
    __int64 *result;
    __int64 i;
    __int64 v3;
    __m128i xmm0;
    __int64 v9;
    struct Struct_1_t *ptr;
    __int64 v5;
    __int64 *dst;
    __int64 v6;

    v8 = 0x736C7468707A2E;
    v10 = 0x636F6C65727A2E;
    result = 0x6E616D6870797A2E;
    a3 = v_370;
    if (a3 != 0) {
        a1 = (__int64 *)v_368;
        a2 = a3 + a3*8;
        a2 += a2*2;
        a2 += a3;
        a3 = 0;
        i = 0;
        while (*(a1 + a3) != a4) {
            ++i;
            a3 += 28;
            *(dst + 8) = 11;
            result = 0x8000000000000000;
            *dst = result;
            if (str != 0) {
                v3 = v_350;
                off_140108030(a1, a2, a3, a4);
                off_140108038(result, 0, v3);
            }
            if (v_360 != 0) {
                v3 = v_368;
                off_140108030();
                off_140108038(result, 0, v3);
            }
            if (v_548 != 0) {
                v3 = v_550;
                off_140108030();
                off_140108038(result, 0, v3);
            }
            if (v_560 != 0) {
                v3 = v_568;
                off_140108030();
                off_140108038(result, 0, v3);
            }
            result = (__int64 *)v_578;
            result = (__int64 *)((__int64)(__int64)result << 1);
            if (result != 0) JUMPOUT(0x1400a7c1c);
            result = (__int64 *)v_590;
            result = (__int64 *)((__int64)(__int64)result << 1);
            if (result == 0) JUMPOUT(0x1400a7c64);
            return sub_1400A7C48();
        }
        a2 = i + i*8;
        a2 += a2*2;
        a2 += i;
        v3 = *(a1 + a2 + 16);
        if (v3 != 0) {
            a3 = *(a1 + a2 + 20);
            a3 += v3;
            if (a3 <= v_358) {
                v_d0 = v6;
                v_f0 = v9;
                v_138 = v8;
                v_258 = (__int64)result;
                result = *(a1 + a2 + 12);
                v_b8 = (__int64)result;
                v_a70 = (__int64)ptr;
                sub_14002EDF0(0, 6, a3, 0x747865742E);
                if (result == 0) JUMPOUT(0x1400ae75a);
                *(result + 4) = 0x6465;
                *result = 0x7466696C;
                v_5f0 = 6;
                v_5f8 = (__int64)result;
                v_600 = 6;
                v_608 = 0;
                v_610 = 8;
                xmm0 = _mm_setzero_si128();
                _mm_storeu_si128((__m128i *)&v_618, xmm0);
                v_628 = 8;
                _mm_storeu_si128((__m128i *)&v_630, xmm0);
                v_640 = 8;
                v_648 = 0;
                v_650 = 1;
                a1 = rsp + 768;
                sub_14006EC70(a1, str);
                v8 = v_350;
                v9 = v_358;
                result = (__int64 *)v_300;
                v_80 = (__int64)result;
                ptr = (struct Struct_1_t *)v_308;
                a1 = (__int64 *)v_310;
                v5 = 0xAAAAAAAAAAAAAAAB;
                result = (__int64 *)ptr;
                if (a1 == 0) JUMPOUT(0x1400a7cb9);
                a1 = (__int64 *)((__int64)(__int64)a1 << 2);
                a3 = a1 + (__int64)(__int64)a1*2;
                a1 = a3 - 12;
                result = a1;
                result = (__int64 *)((__int64)(__int64)(__int64)result * v5); /* unsigned; high half in a2 */;
                a2 = (int)ptr;
                result = (__int64 *)ptr;
                if ((((a2 >> 3) & 1))) JUMPOUT(0x1400a7caf);
                result = ptr->field_0;
                a4 = ptr->field_4;
                a2 = ptr + 12;
                if (a4 <= result) JUMPOUT(0x1400a7cac);
                *(__int64 *)ptr = (__int64)(result);
                ptr->field_4 = a4;
                result = ptr + 12;
                return sub_1400A7CAF();
            }
        }
    }
    return (__int64)result;
}