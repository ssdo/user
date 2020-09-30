package user

import (
	"fmt"
	"github.com/ssgo/u"
	"strings"
)

func EncryptPhone(phone string, offset uint64) string {
	tag := 0
	if phone[0] == '+' {
		tag |= 1
		phone = phone[1:]
	}

	foundCount := uint(0)
	n := uint(len(phone))
	for i := uint(1); i < n; i++ {
		if phone[i] == '-' {
			foundCount++
			//fmt.Println("      @@@", i-foundCount)
			tag |= 1 << (i - foundCount)
		}
	}

	if tag > 1 {
		phone = strings.ReplaceAll(phone, "-", "")
	}

	buf := u.EncodeInt(u.Uint64(phone) + offset)
	buf = append(buf, u.EncodeInt(uint64(len(phone)))...)
	if tag > 0 {
		tagBuf := u.EncodeInt(uint64(tag))
		buf = append(buf, '-')
		buf = append(buf, tagBuf...)
	}

	//fmt.Println("  ###", phone, tag, string(buf))
	return string(buf)
}

func DecryptPhone(phoneX string, offset uint64) string {
	tagX := ""
	tagPos := strings.IndexByte(phoneX, '-')
	if tagPos != -1 {
		tagX = phoneX[tagPos+1:]
		phoneX = phoneX[0:tagPos]
	}
	phoneFixedLen := int(u.DecodeInt([]byte{phoneX[len(phoneX)-1]}))
	phoneX = phoneX[0 : len(phoneX)-1]

	phoneArr := make([]string, 0)
	madeLen := uint(0)
	phone := u.String(u.DecodeInt([]byte(phoneX)) - offset)
	if len(phone) < phoneFixedLen {
		phone = fmt.Sprintf("%0"+u.String(phoneFixedLen)+"s", phone)
	}
	if tagX != "" {
		tag := u.DecodeInt([]byte(tagX))
		if tag&1 == 1 {
			phoneArr = append(phoneArr, "+")
		}
		for i := uint(1); i < 20; i++ {
			j := tag >> i
			if j == 0 {
				break
			}
			if j&1 == 1 {
				phoneArr = append(phoneArr, phone[madeLen:i+1], "-")
				madeLen = i + 1
			}
			//fmt.Println("^^^", i, j, j & 1)
		}
		phoneArr = append(phoneArr, phone[madeLen:])
		phone = strings.Join(phoneArr, "")

		//fmt.Println("  ---", phone, tagX, tag, tag&1)
	}

	return phone
}
