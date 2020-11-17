#pragma once

template <int X> struct EnsureCompileTime {
	enum : int {
		Value = X
	};
};
#define Seed ((__TIME__[7] - '0') * 1  + (__TIME__[6] - '0') * 10  + \
	(__TIME__[4] - '0') * 60 + (__TIME__[3] - '0') * 600 + \
	(__TIME__[1] - '0') * 3600 + (__TIME__[0] - '0') * 36000)

__forceinline constexpr int LinearCongruentGenerator(int Rounds) {
	return 1013904223 + 1664525 * ((Rounds > 0) ? LinearCongruentGenerator(Rounds - 1) : Seed & 0xFFFFFFFF);
}
#define Random() EnsureCompileTime<LinearCongruentGenerator(15)>::Value 
#define RandomNumber(Min, Max) (Min + (Random() % (Max - Min + 1)))
template <int... Pack> struct IndexList {};
template <typename IndexList, int Right> struct Append;
template <int... Left, int Right> struct Append<IndexList<Left...>, Right> {
	typedef IndexList<Left..., Right> Result;
};
template <int N> struct ConstructIndexList {
	typedef typename Append<typename ConstructIndexList<N - 1>::Result, N - 1>::Result Result;
};
template <> struct ConstructIndexList<0> {
	typedef IndexList<> Result;
};
const char XORKEY_A = static_cast<char>(0x13);
const wchar_t XORKEY_W = static_cast<wchar_t>(0x133);
__declspec(noinline)  constexpr char EncryptCharacterA(const char Character, int Index) {
	return Character ^ (XORKEY_A + Index);
}
template <typename IndexList> class CingA;
template <int... Index> class CingA<IndexList<Index...> > {
private:
	char Value[sizeof...(Index) + 1];
public:
	__forceinline constexpr CingA(const char* const String)
		: Value{ EncryptCharacterA(String[Index], Index)... } {}

	__forceinline char* decrypt() {
		for (int t = 0; t < sizeof...(Index); t++) {
			Value[t] = Value[t] ^ (XORKEY_A + t);
		}
		Value[sizeof...(Index)] = '\0';
		return Value;
	}

	__forceinline char* get() {
		return Value;
	}
};
__declspec(noinline) constexpr wchar_t EncryptCharacterW(const wchar_t Character, int Index) {
	return Character ^ (XORKEY_W + Index);
}
template <typename IndexList> class CingW;
template <int... Index> class CingW<IndexList<Index...> > {
private:
	wchar_t Value[sizeof...(Index) + 1];
public:
	__forceinline constexpr CingW(const wchar_t* const String)
		: Value{ EncryptCharacterW(String[Index], Index)... } {}

	__forceinline wchar_t* decrypt() {
		for (int t = 0; t < sizeof...(Index); t++) {
			Value[t] = Value[t] ^ (XORKEY_W + t);
		}
		Value[sizeof...(Index)] = '\0\0';
		return Value;
	}

	__forceinline wchar_t* get() {
		return Value;
	}
};

#define xor_a( String ) ( CingA<ConstructIndexList<sizeof( String ) - 1>::Result>( String ).decrypt() )  
#define xor_w( String ) ( CingW<ConstructIndexList<sizeof( String ) - 1>::Result>( String ).decrypt() )  
