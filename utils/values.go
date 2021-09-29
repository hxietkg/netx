/*
Copyright © 2021 Hongsheng Xie
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"fmt"
)

func GetInt8Val(data []byte, offset int) uint {
	return uint(data[offset])
}

func GetInt16Val(data []byte, offset int) uint {
	return GetInt8Val(data, offset) * 256 +
	       GetInt8Val(data, offset + 1)
}

func GetInt32Val(data []byte, offset int) uint {
	return (GetInt16Val(data, offset) << 16) +
	       GetInt16Val(data, offset + 2)
}

func GetInt64Val(data []byte, offset int) uint {
	return (GetInt32Val(data, offset) << 32) +
	       GetInt32Val(data, offset + 4)
}

func GetHexStr(data []byte, offset int, length int) string {
	str := ""
	for i := 0; i < length; i++ {
		str += fmt.Sprintf("%02x", data[offset + i] & 0xff)
	}
	return str
}