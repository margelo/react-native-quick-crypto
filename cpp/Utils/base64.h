/*
   base64.h

   base64 encoding and decoding with C++.
   More information at
     https://renenyffenegger.ch/notes/development/Base64/Encoding-and-decoding-base-64-with-cpp

   Version: 2.rc.09 (release candidate)

   Copyright (C) 2004-2017, 2020-2022 René Nyffenegger

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   René Nyffenegger rene.nyffenegger@adp-gmbh.ch
*/
/**
 * Copyright (C) 2023 Kevin Heifner
 *
 * Modified to be header only.
 * Templated for std::string, std::string_view, std::vector<char> and other char containers.
 */

#pragma once

#include <algorithm>
#include <string>
#include <string_view>
#include <stdexcept>

// Interface:
// Defaults allow for use:
//   std::string s = "foobar";
//   std::string encoded = base64_encode(s);
//   std::string_view sv = "foobar";
//   std::string encoded = base64_encode(sv);
//   std::vector<char> vc = {'f', 'o', 'o'};
//   std::string encoded = base64_encode(vc);
//
// Also allows for user provided char containers and specified return types:
//   std::string s = "foobar";
//   std::vector<char> encoded = base64_encode<std::vector<char>>(s);

template <typename RetString = std::string, typename String = std::string>
RetString base64_encode(const String& s, bool url = false);

template <typename RetString = std::string, typename String = std::string>
RetString base64_encode_pem(const String& s);

template <typename RetString = std::string, typename String = std::string>
RetString base64_encode_mime(const String& s);

template <typename RetString = std::string, typename String = std::string>
RetString base64_decode(const String& s, bool remove_linebreaks = false);

template <typename RetString = std::string>
RetString base64_encode(const unsigned char* s, size_t len, bool url = false);

namespace detail {
 //
 // Depending on the url parameter in base64_chars, one of
 // two sets of base64 characters needs to be chosen.
 // They differ in their last two characters.
 //
constexpr const char* to_base64_chars[2] = {
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789"
             "+/",

             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789"
             "-_"};

constexpr unsigned char from_base64_chars[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 62, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

inline unsigned int pos_of_char(const unsigned char chr) {
   //
   // Return the position of chr within base64_encode()
   //

   if (from_base64_chars[chr] != 64) return from_base64_chars[chr];

   //
   // 2020-10-23: Throw std::exception rather than const char*
   //(Pablo Martin-Gomez, https://github.com/Bouska)
   //
   throw std::runtime_error("Input is not valid base64-encoded data.");
}

template <typename RetString, typename String>
inline RetString insert_linebreaks(const String& str, size_t distance) {
   //
   // Provided by https://github.com/JomaCorpFX, adapted by Rene & Kevin
   //
   if (!str.size()) {
      return RetString{};
   }

   if (distance < str.size()) {
      size_t pos = distance;
      String s{str};
      while (pos < s.size()) {
         s.insert(pos, "\n");
         pos += distance + 1;
      }
      return s;
   } else {
      return str;
   }
}

template <typename RetString, typename String, unsigned int line_length>
inline RetString encode_with_line_breaks(String s) {
   return insert_linebreaks<RetString, String>(base64_encode(s, false), line_length);
}

template <typename RetString, typename String>
inline RetString encode_pem(String s) {
   return encode_with_line_breaks<RetString, String, 64>(s);
}

template <typename RetString, typename String>
inline RetString encode_mime(String s) {
   return encode_with_line_breaks<RetString, String, 76>(s);
}

template <typename RetString, typename String>
inline RetString encode(String s, bool url) {
   return base64_encode<RetString>(reinterpret_cast<const unsigned char*>(s.data()), s.size(), url);
}

} // namespace detail

template <typename RetString>
inline RetString base64_encode(const unsigned char* bytes_to_encode, size_t in_len, bool url) {
   size_t len_encoded = (in_len + 2) / 3 * 4;

   unsigned char trailing_char = url ? '.' : '=';

   //
   // Choose set of base64 characters. They differ
   // for the last two positions, depending on the url
   // parameter.
   // A bool (as is the parameter url) is guaranteed
   // to evaluate to either 0 or 1 in C++ therefore,
   // the correct character set is chosen by subscripting
   // base64_chars with url.
   //
   const char *base64_chars_ = detail::to_base64_chars[url];

   RetString ret;
   ret.reserve(len_encoded);

   unsigned int pos = 0;

   while (pos < in_len) {
      ret.push_back(base64_chars_[(bytes_to_encode[pos + 0] & 0xfc) >> 2]);

      if (pos + 1 < in_len) {
         ret.push_back(base64_chars_[((bytes_to_encode[pos + 0] & 0x03) << 4) +
                                     ((bytes_to_encode[pos + 1] & 0xf0) >> 4)]);

         if (pos + 2 < in_len) {
            ret.push_back(base64_chars_[((bytes_to_encode[pos + 1] & 0x0f) << 2) +
                                        ((bytes_to_encode[pos + 2] & 0xc0) >> 6)]);
            ret.push_back(base64_chars_[bytes_to_encode[pos + 2] & 0x3f]);
         } else {
            ret.push_back(base64_chars_[(bytes_to_encode[pos + 1] & 0x0f) << 2]);
            ret.push_back(trailing_char);
         }
      } else {
         ret.push_back(base64_chars_[(bytes_to_encode[pos + 0] & 0x03) << 4]);
         ret.push_back(trailing_char);
         ret.push_back(trailing_char);
      }

      pos += 3;
   }

   return ret;
}

namespace detail {

template <typename RetString, typename String>
inline RetString decode(const String& encoded_string, bool remove_linebreaks) {
    static_assert(!std::is_same<RetString, std::string_view>::value,
                  "RetString should not be std::string_view");

   //
   // decode(…) is templated so that it can be used with String = const std::string&
   // or std::string_view (requires at least C++17)
   //

   if (encoded_string.empty())
      return RetString{};

   if (remove_linebreaks) {
      String copy{encoded_string};

      copy.erase(std::remove(copy.begin(), copy.end(), '\n'), copy.end());

      return base64_decode<RetString, String>(copy, false);
   }

   size_t length_of_string = encoded_string.size();
   size_t pos = 0;

   //
   // The approximate length (bytes) of the decoded string might be one or
   // two bytes smaller, depending on the amount of trailing equal signs
   // in the encoded string. This approximation is needed to reserve
   // enough space in the string to be returned.
   //
   size_t approx_length_of_decoded_string = length_of_string / 4 * 3;
   RetString ret;
   ret.reserve(approx_length_of_decoded_string);

   while (pos < length_of_string) {
      //
      // Iterate over encoded input string in chunks. The size of all
      // chunks except the last one is 4 bytes.
      //
      // The last chunk might be padded with equal signs or dots
      // in order to make it 4 bytes in size as well, but this
      // is not required as per RFC 2045.
      //
      // All chunks except the last one produce three output bytes.
      //
      // The last chunk produces at least one and up to three bytes.
      //

      size_t pos_of_char_1 = pos_of_char(encoded_string.at(pos + 1));

      //
      // Emit the first output byte that is produced in each chunk:
      //
      ret.push_back(static_cast<typename RetString::value_type>(((pos_of_char(encoded_string.at(pos + 0))) << 2) + ((pos_of_char_1 & 0x30) >> 4)));

      if ((pos + 2 < length_of_string) &&
          // Check for data that is not padded with equal signs (which is allowed by RFC 2045)
          encoded_string.at(pos + 2) != '=' &&
          encoded_string.at(pos + 2) != '.' ) {     // accept URL-safe base 64 strings, too, so check for '.' also.
         //
         // Emit a chunk's second byte (which might not be produced in the last chunk).
         //
         unsigned int pos_of_char_2 = pos_of_char(encoded_string.at(pos + 2));
         ret.push_back(static_cast<typename RetString::value_type>(((pos_of_char_1 & 0x0f) << 4) + ((pos_of_char_2 & 0x3c) >> 2)));

         if ((pos + 3 < length_of_string) &&
             encoded_string.at(pos + 3) != '=' &&
             encoded_string.at(pos + 3) != '.' ) {
            //
            // Emit a chunk's third byte (which might not be produced in the last chunk).
            //
            ret.push_back(static_cast<typename RetString::value_type>(((pos_of_char_2 & 0x03) << 6) + pos_of_char(encoded_string.at(pos + 3))));
         }
      }

      pos += 4;
   }

   return ret;
}

} // namespace detail

template <typename RetString, typename String>
inline RetString base64_decode(const String& s, bool remove_linebreaks) {
   return detail::decode<RetString, String>(s, remove_linebreaks);
}

template <typename RetString, typename String>
inline RetString base64_encode(const String& s, bool url) {
   return detail::encode<RetString, String>(s, url);
}

template <typename RetString, typename String>
inline RetString base64_encode_pem (const String& s) {
   return detail::encode_pem<RetString, String>(s);
}

template <typename RetString, typename String>
inline RetString base64_encode_mime(const String& s) {
   return detail::encode_mime<RetString, String>(s);
}