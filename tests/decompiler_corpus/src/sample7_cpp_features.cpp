// Broad C++ feature coverage for decompiler RE testing:
//  - virtual dispatch (vtables), abstract base + override
//  - templates (monomorphized), operator overloading
//  - RAII / destructors, new/delete (heap)
//  - exceptions (try/catch/throw), references
//  - STL: std::vector, std::string, std::map, iterators, algorithms
//  - lambdas / std::function, namespaces, enum class
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <numeric>
#include <algorithm>
#include <functional>
#include <stdexcept>

namespace shapes {

enum class Kind : uint8_t { Circle, Square, Triangle };

// Abstract base → vtable + pure virtual.
class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
    virtual Kind kind() const = 0;
};

class Circle final : public Shape {
    double r_;
public:
    explicit Circle(double r) : r_(r) {}
    double area() const override { return 3.14159265358979 * r_ * r_; }
    Kind kind() const override { return Kind::Circle; }
};

class Square final : public Shape {
    double s_;
public:
    explicit Square(double s) : s_(s) {}
    double area() const override { return s_ * s_; }
    Kind kind() const override { return Kind::Square; }
};

} // namespace shapes

// Template — will monomorphize per type used.
template <typename T>
static T clamp_val(T v, T lo, T hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

// Operator overloading + small value type.
struct Vec2 {
    double x, y;
    Vec2 operator+(const Vec2 &o) const { return Vec2{x + o.x, y + o.y}; }
    double dot(const Vec2 &o) const { return x * o.x + y * o.y; }
};

// Exceptions.
static int checked_div(int a, int b) {
    if (b == 0) throw std::runtime_error("divide by zero");
    return a / b;
}

extern "C" double total_area(int n) {
    using namespace shapes;
    // Heap allocation + polymorphism + RAII cleanup.
    std::vector<Shape *> v;
    for (int i = 0; i < n; ++i) {
        if (i % 2 == 0) v.push_back(new Circle(double(i)));
        else v.push_back(new Square(double(i)));
    }
    double sum = 0.0;
    for (Shape *s : v) sum += s->area();      // virtual dispatch
    for (Shape *s : v) delete s;              // destructors
    return sum;
}

extern "C" int64_t string_map_demo(int n) {
    std::map<std::string, int64_t> counts;
    std::vector<std::string> words = {"alpha", "beta", "alpha", "gamma", "beta", "alpha"};
    for (int i = 0; i < n && i < (int)words.size(); ++i) {
        counts[words[i]] += 1;              // map insert / find
    }
    int64_t total = 0;
    for (const auto &kv : counts) total += kv.second * (int64_t)kv.first.size();
    // Lambda + std::function + algorithm.
    std::function<int64_t(int64_t)> sq = [](int64_t x) { return x * x; };
    std::vector<int64_t> nums(n);
    std::iota(nums.begin(), nums.end(), 1);
    std::transform(nums.begin(), nums.end(), nums.begin(), [&](int64_t x){ return sq(x); });
    total += std::accumulate(nums.begin(), nums.end(), int64_t{0});
    return total;
}

int main() {
    Vec2 a{1.0, 2.0}, b{3.0, 4.0};
    Vec2 c = a + b;
    double d = c.dot(b) + clamp_val(total_area(5), 0.0, 1e9);
    int64_t m = string_map_demo(6);
    int q = 0;
    try { q = checked_div(10, 0); } catch (const std::exception &) { q = -1; }
    return (int)(d + (double)m + (double)q);
}
