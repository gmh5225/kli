/*
 * Copyright 2022 Adrian Johnsen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HV_KLI_HPP
#define HV_KLI_HPP

#pragma warning( disable : 5040)

#include <intrin.h>

#ifdef _MSC_VER
#define _KLI_FORCEINLINE __forceinline
#else
#define _KLI_FORCEINLINE __attribute__((always_inline))
#endif

#ifndef KLI_DONT_INLINE
#define KLI_FORCEINLINE _KLI_FORCEINLINE
#else
#define KLI_FORCEINLINE inline
#endif

namespace clonestd
{
	// STRUCT TEMPLATE remove_reference
	template <class _Ty>
	struct remove_reference {
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_reference<_Ty&> {
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_reference<_Ty&&> {
		using type = _Ty;
	};

	template <class _Ty>
	using remove_reference_t = typename remove_reference<_Ty>::type;

	// STRUCT TEMPLATE remove_const
	template <class _Ty>
	struct remove_const { // remove top-level const qualifier
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_const<const _Ty> {
		using type = _Ty;
	};

	template <class _Ty>
	using remove_const_t = typename remove_const<_Ty>::type;
}

#define KLI_FN(name) ((decltype(&##name))(::kli::find_kernel_export(KLI_HASH_STR(#name))))

namespace kli {
	namespace cache {
		inline unsigned long long base;
	}

	namespace literals {
		KLI_FORCEINLINE constexpr unsigned long long operator ""_KiB(unsigned long long num) { return num << 10; }
		KLI_FORCEINLINE constexpr unsigned long long operator ""_MiB(unsigned long long num) { return num << 20; }
		KLI_FORCEINLINE constexpr unsigned long long operator ""_GiB(unsigned long long num) { return num << 30; }
		KLI_FORCEINLINE constexpr unsigned long long operator ""_TiB(unsigned long long num) { return num << 40; }
	}
	using namespace literals;

	namespace hash {
		namespace detail {
			template <typename Size>
			struct fnv_constants;

			template <>
			struct fnv_constants<unsigned int>
			{
				constexpr static unsigned int default_offset_basis = 0x811C9DC5UL;
				constexpr static unsigned int prime = 0x01000193UL;
			};

			template <>
			struct fnv_constants<unsigned long long>
			{
				constexpr static unsigned long long default_offset_basis = 0xCBF29CE484222325ULL;
				constexpr static unsigned long long prime = 0x100000001B3ULL;
			};

			template <typename Char>
			struct char_traits;

			template <>
			struct char_traits<char>
			{
				KLI_FORCEINLINE static constexpr char to_lower(char c) { return c | ' '; };
				KLI_FORCEINLINE static constexpr char to_upper(char c) { return c & '_'; }; // equivalent to c & ~' '
				KLI_FORCEINLINE static constexpr char flip_case(char c) { return c ^ ' '; };
				KLI_FORCEINLINE static constexpr bool is_caps(char c) { return (c & ' ') == ' '; }
			};

			template <>
			struct char_traits<wchar_t>
			{
				KLI_FORCEINLINE static constexpr wchar_t to_lower(wchar_t c) { return c | L' '; };
				KLI_FORCEINLINE static constexpr wchar_t to_upper(wchar_t c) { return c & L'_'; }; // equivalent to c & ~' '
				KLI_FORCEINLINE static constexpr wchar_t flip_case(wchar_t c) { return c ^ L' '; };
				KLI_FORCEINLINE static constexpr bool is_caps(wchar_t c) { return (c & L' ') == L' '; }
			};
		}

		// Shortcuts for character traits
		template <typename Char> KLI_FORCEINLINE constexpr Char to_lower(Char c) { return detail::char_traits<Char>::to_lower(c); }
		template <typename Char> KLI_FORCEINLINE constexpr Char to_upper(Char c) { return detail::char_traits<Char>::to_upper(c); }
		template <typename Char> KLI_FORCEINLINE constexpr Char flip_case(Char c) { return detail::char_traits<Char>::flip_case(c); }

		template <typename Type, typename Char, bool ToLower = false>
		KLI_FORCEINLINE constexpr Type hash_fnv1a(const Char* str)
		{
			Type val = detail::fnv_constants<Type>::default_offset_basis;

			for (; *str != static_cast<Char>(0); ++str) {
				Char c = *str;

				if constexpr (ToLower)
					c = to_lower<Char>(c);

				val ^= static_cast<Type>(c);
				val *= static_cast<Type>(detail::fnv_constants<Type>::prime);
			}

			return val;
		}

		// Dumb hack to force a constexpr value to be evaluated in compiletime
		template <typename Type, Type Value>
		struct force_cx
		{
			constexpr static auto value = Value;
		};

#define _KLI_HASH_RTS(str) (::kli::hash::hash_fnv1a<unsigned long long, clonestd::remove_const_t<clonestd::remove_reference_t<decltype(*(str))>>, false>((str)))
#define _KLI_HASH_RTS_TOLOWER(str) (::kli::hash::hash_fnv1a<unsigned long long, clonestd::remove_const_t<clonestd::remove_reference_t<decltype(*(str))>>, true>((str)))

#define _KLI_HASH_STR(str) (::kli::hash::force_cx<unsigned long long, ::kli::hash::hash_fnv1a<unsigned long long, clonestd::remove_const_t<clonestd::remove_reference_t<decltype(*(str))>>, false>((str))>::value)
#define _KLI_HASH_STR_TOLOWER(str) (::kli::hash::force_cx<unsigned long long, ::kli::hash::hash_fnv1a<unsigned long long, clonestd::remove_const_t<clonestd::remove_reference_t<decltype(*(str))>>, true>((str))>::value)

#ifndef KLI_USE_TOLOWER
		// Don't use tolower
#define KLI_HASH_RTS(str) _KLI_HASH_RTS(str)
#define KLI_HASH_STR(str) _KLI_HASH_STR(str)
#else
		// Use tolower
#define KLI_HASH_RTS(str) _KLI_HASH_RTS_TOLOWER(str)
#define KLI_HASH_STR(str) _KLI_HASH_STR_TOLOWER(str)
#endif
	}

	namespace detail {
		typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
			unsigned short   e_magic;                     // Magic number
			unsigned short   e_cblp;                      // Bytes on last page of file
			unsigned short   e_cp;                        // Pages in file
			unsigned short   e_crlc;                      // Relocations
			unsigned short   e_cparhdr;                   // GetSize of header in paragraphs
			unsigned short   e_minalloc;                  // Minimum extra paragraphs needed
			unsigned short   e_maxalloc;                  // Maximum extra paragraphs needed
			unsigned short   e_ss;                        // Initial (relative) SS value
			unsigned short   e_sp;                        // Initial SP value
			unsigned short   e_csum;                      // Checksum
			unsigned short   e_ip;                        // Initial IP value
			unsigned short   e_cs;                        // Initial (relative) CS value
			unsigned short   e_lfarlc;                    // File address of relocation table
			unsigned short   e_ovno;                      // Overlay number
			unsigned short   e_res[4];                    // Reserved words
			unsigned short   e_oemid;                     // OEM identifier (for e_oeminfo)
			unsigned short   e_oeminfo;                   // OEM information; e_oemid specific
			unsigned short   e_res2[10];                  // Reserved words
			int    e_lfanew;                    // File address of new exe header
		} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

		typedef struct _IMAGE_FILE_HEADER {
			unsigned short    Machine;
			unsigned short    NumberOfSections;
			unsigned int   TimeDateStamp;
			unsigned int   PointerToSymbolTable;
			unsigned int   NumberOfSymbols;
			unsigned short    SizeOfOptionalHeader;
			unsigned short    Characteristics;
		} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

		typedef struct _IMAGE_DATA_DIRECTORY {
			unsigned int   VirtualAddress;
			unsigned int   Size;
		} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

		typedef struct _IMAGE_OPTIONAL_HEADER64 {
			unsigned short        Magic;
			unsigned char        MajorLinkerVersion;
			unsigned char        MinorLinkerVersion;
			unsigned int       SizeOfCode;
			unsigned int       SizeOfInitializedData;
			unsigned int       SizeOfUninitializedData;
			unsigned int       AddressOfEntryPoint;
			unsigned int       BaseOfCode;
			unsigned long long   ImageBase;
			unsigned int       SectionAlignment;
			unsigned int       FileAlignment;
			unsigned short        MajorOperatingSystemVersion;
			unsigned short        MinorOperatingSystemVersion;
			unsigned short        MajorImageVersion;
			unsigned short        MinorImageVersion;
			unsigned short        MajorSubsystemVersion;
			unsigned short        MinorSubsystemVersion;
			unsigned int       Win32VersionValue;
			unsigned int       SizeOfImage;
			unsigned int       SizeOfHeaders;
			unsigned int       CheckSum;
			unsigned short        Subsystem;
			unsigned short        DllCharacteristics;
			unsigned long long   SizeOfStackReserve;
			unsigned long long   SizeOfStackCommit;
			unsigned long long   SizeOfHeapReserve;
			unsigned long long   SizeOfHeapCommit;
			unsigned int       LoaderFlags;
			unsigned int       NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[16];
		} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

		typedef struct _IMAGE_NT_HEADERS64 {
			unsigned int Signature;
			IMAGE_FILE_HEADER FileHeader;
			IMAGE_OPTIONAL_HEADER64 OptionalHeader;
		} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

		typedef struct _IMAGE_EXPORT_DIRECTORY {
			unsigned int   Characteristics;
			unsigned int   TimeDateStamp;
			unsigned short   MajorVersion;
			unsigned short   MinorVersion;
			unsigned int   Name;
			unsigned int   Base;
			unsigned int   NumberOfFunctions;
			unsigned int   NumberOfNames;
			unsigned int   AddressOfFunctions;     // RVA from base of image
			unsigned int   AddressOfNames;         // RVA from base of image
			unsigned int   AddressOfNameOrdinals;  // RVA from base of image
		} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

		constexpr auto IMAGE_DIRECTORY_ENTRY_EXPORT = 0;

		KLI_FORCEINLINE unsigned long long get_kernel_base()
		{
			auto Idt_base = (unsigned long long)KeGetPcr()->IdtBase;
			auto align_page = *(unsigned long long*)(Idt_base + 4) >> 0xc << 0xc;

			for (; align_page; align_page -= PAGE_SIZE)
			{
				for (int index = 0; index < PAGE_SIZE - 0x7; index++)
				{
					auto current_address = static_cast<long long>(align_page) + index;
					if
						(
							( //SeSetAuditParameter
								*(unsigned char*)current_address == 0x48
								&& *(unsigned char*)(current_address + 1) == 0x8D
								&& *(unsigned char*)(current_address + 2) == 0x3D
								&& *(unsigned char*)(current_address + 6) == 0xFF
								&& *(unsigned char*)(current_address + 7) == 0x48
								&& *(unsigned char*)(current_address + 8) == 0x63
								)
							||

							( //VfPowerDumpIrpStack
								*(unsigned char*)current_address == 0x48
								&& *(unsigned char*)(current_address + 1) == 0x8D
								&& *(unsigned char*)(current_address + 2) == 0x3D
								&& *(unsigned char*)(current_address + 6) == 0xFF
								&& *(unsigned char*)(current_address + 7) == 0x48
								&& *(unsigned char*)(current_address + 8) == 0x8B
								&& *(unsigned char*)(current_address + 9) == 0x8C
								&& *(unsigned char*)(current_address + 15) == 0xE8
								)
							||
							( //RtlMapSecurityErrorToNtStatus
								*(unsigned char*)current_address == 0x4C
								&& *(unsigned char*)(current_address + 1) == 0x8D
								&& *(unsigned char*)(current_address + 2) == 0x3D
								&& *(unsigned char*)(current_address + 6) == 0xFF
								&& *(unsigned char*)(current_address + 7) == 0x48
								&& *(unsigned char*)(current_address + 8) == 0x98
								)
							)
					{
						auto nto_base_offset = *(int*)(current_address + 3);
						auto nto_base_ = current_address + nto_base_offset + 7;
						if (!(nto_base_ & 0xfff))
						{
							return nto_base_;
						}
					}
				}
			}
			return NULL;
		}
	}

	KLI_FORCEINLINE unsigned long long find_kernel_export(unsigned long long export_hash)
	{
		if (!cache::base)
			cache::base = detail::get_kernel_base();

		const auto dos_header = (detail::PIMAGE_DOS_HEADER)cache::base;
		const auto nt_headers = (detail::PIMAGE_NT_HEADERS64)(cache::base + dos_header->e_lfanew);
		const auto export_directory = (detail::PIMAGE_EXPORT_DIRECTORY)(cache::base +
			nt_headers->OptionalHeader.DataDirectory[detail::IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		const auto address_of_functions = (unsigned int*)(cache::base + export_directory->AddressOfFunctions);
		const auto address_of_names = (unsigned int*)(cache::base + export_directory->AddressOfNames);
		const auto address_of_name_ordinals = (unsigned short*)(cache::base + export_directory->AddressOfNameOrdinals);

		for (unsigned int i = 0; i < export_directory->NumberOfNames; ++i)
		{
			const auto export_entry_name = (char*)(cache::base + address_of_names[i]);
			const auto export_entry_hash = KLI_HASH_RTS(export_entry_name);

			
			// address_of_functions is indexed through an ordinal
			// address_of_name_ordinals gets the ordinal through our own index - i.
			if (export_entry_hash == export_hash)
				return cache::base + address_of_functions[address_of_name_ordinals[i]];
		}

		return 0ULL;
	}
}

#endif // include guard
