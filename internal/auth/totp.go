package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func VerifyTOTP(secret, code string, now time.Time) bool {
	if len(code) != totpDigits {
		return false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return false
	}
	counter := now.Unix() / totpPeriodSeconds
	for skew := -totpAllowedSkewWindow; skew <= totpAllowedSkewWindow; skew++ {
		if GenerateTOTP(secret, counter+int64(skew), totpDigits) == code {
			return true
		}
	}
	return false
}

func GenerateTOTP(secret string, counter int64, digits int) string {
	if counter < 0 || digits <= 0 || digits > 8 {
		return ""
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, decoded)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	modulo := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, binCode%modulo)
}

func provisioningURI(issuer, accountLabel, secret string) string {
	label := url.PathEscape(issuer + ":" + accountLabel)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", strconv.Itoa(totpDigits))
	q.Set("period", strconv.Itoa(totpPeriodSeconds))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
