// Broad C# feature coverage for decompiler RE testing (Native AOT → real PE):
//  - interfaces + virtual dispatch, abstract base + override
//  - generics (List<T>, Dictionary<K,V>), delegates / Func<>, LINQ-ish
//  - structs, properties, exceptions (try/catch/throw)
//  - arrays, foreach, pattern matching (switch expression)
using System;
using System.Collections.Generic;

interface IShape
{
    double Area();
}

abstract class Shape : IShape
{
    public abstract double Area();
}

sealed class Circle : Shape
{
    private readonly double _r;
    public Circle(double r) { _r = r; }
    public override double Area() => 3.14159265358979 * _r * _r;
}

sealed class Rect : Shape
{
    public double W { get; }
    public double H { get; }
    public Rect(double w, double h) { W = w; H = h; }
    public override double Area() => W * H;
}

struct Vec2
{
    public double X, Y;
    public double Dot(Vec2 o) => X * o.X + Y * o.Y;
}

enum Op { Add, Sub, Mul }

static class Program
{
    static long Apply(Op op, long a, long b) => op switch
    {
        Op.Add => a + b,
        Op.Sub => a - b,
        Op.Mul => a * b,
        _ => 0,
    };

    static long CheckedDiv(long a, long b)
    {
        if (b == 0) throw new DivideByZeroException();
        return a / b;
    }

    static double TotalArea(int n)
    {
        var shapes = new List<IShape>();
        for (int i = 0; i < n; i++)
        {
            if (i % 2 == 0) shapes.Add(new Circle(i));
            else shapes.Add(new Rect(i, i + 1));
        }
        double sum = 0;
        foreach (var s in shapes) sum += s.Area(); // interface dispatch
        return sum;
    }

    static long DictAndDelegate(int n)
    {
        var counts = new Dictionary<string, long>();
        string[] words = { "a", "b", "a", "c", "b", "a" };
        for (int i = 0; i < n && i < words.Length; i++)
        {
            counts.TryGetValue(words[i], out long c);
            counts[words[i]] = c + 1;
        }
        long total = 0;
        foreach (var kv in counts) total += kv.Value * kv.Key.Length;
        Func<long, long> sq = x => x * x; // delegate
        for (long i = 1; i <= n; i++) total += sq(i);
        return total;
    }

    static int Main()
    {
        double a = TotalArea(5);
        long d = DictAndDelegate(6);
        long op = Apply(Op.Mul, 6, 7) + Apply(Op.Add, 3, 4);
        var v = new Vec2 { X = 1, Y = 2 };
        double dot = v.Dot(new Vec2 { X = 3, Y = 4 });
        long q;
        try { q = CheckedDiv(10, 0); } catch (DivideByZeroException) { q = -1; }
        return (int)(a + d + op + dot + q);
    }
}
