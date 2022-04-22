package user

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/fogleman/gg"
	"github.com/ssgo/u"
)

var fontFiles = []string{"fonts/Flim-Flam.ttf", "fonts/Comismsh.ttf", "fonts/chromohv.ttf", "fonts/actionj.ttf", "fonts/RitaSmith.ttf", "fonts/DeborahFancyDress.ttf", "fonts/DENNEthree-dee.ttf", "fonts/ApothecaryFont.ttf"}

func DefaultTokenMaker() []byte {
	token := make([]byte, 10)
	for i := 0; i < 10; i++ {
		token[i] = byte(u.GlobalRand1.Intn(255))
	}
	return token
}

func DefaultSaltMaker() string {
	return base64.StdEncoding.EncodeToString(DefaultTokenMaker())
}

func DefaultSecretMaker(userId string, token []byte) string {
	hash := sha256.New()
	hash.Write([]byte(userId))
	hash.Write(token)
	return base64.StdEncoding.EncodeToString(hash.Sum([]byte{}))
}

func DefaultSigner(userId, input, salt string) string {
	inputBytes, err := base64.StdEncoding.DecodeString(input)
	if err != nil && inputBytes == nil {
		return input
	}
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil && saltBytes == nil {
		return input
	}
	hash := sha256.New()
	hash.Write([]byte(userId))
	hash.Write(saltBytes)
	hash.Write(inputBytes)
	return base64.StdEncoding.EncodeToString(hash.Sum([]byte{}))
}

func DefaultVerifyCodeMaker() string {
	return fmt.Sprint(ri1s(10), ri2s(10), ri1s(10), ri2s(10), ri1s(10), ri2s(10))
}

func DefaultImageCodeMaker() string {
	return fmt.Sprint(ri1s(10), ri2s(10), ri1s(10), ri2s(10))
}

func DefaultCodeImageMaker(imageCode string) []byte {
	g := gg.NewContext(320, 120)
	g.SetRGB(rf(0.7)+0.3, rf(0.7)+0.3, rf(0.7)+0.3)
	g.DrawRectangle(0, 0, 320, 120)
	g.Fill()
	buf := bytes.NewBuffer(make([]byte, 0))

	startX := float64(0)
	for _, word := range imageCode {
		fontIndex := u.GlobalRand2.Intn(len(fontFiles))
		fontFile := fontFiles[fontIndex]
		face, err := gg.LoadFontFace(fontFile, 80)
		if err == nil {
			g.SetFontFace(face)
		}

		if fontIndex < 4 {
			g.SetRGB(rf(0.4), rf(0.4), rf(0.4))
		} else {
			g.SetRGB(rf(0.6), rf(0.6), rf(0.6))
		}
		startX += rf(50)
		g.DrawStringAnchored(string(word), startX, rf(60)-20, 0, 1)
		startX += 40
	}

	noiseSize := float64(15)
	for i := 0; i < 100; i++ {
		g.SetRGB(rf(0.8)+0.2, rf(0.8)+0.2, rf(0.8)+0.2)
		switch u.GlobalRand1.Intn(4) {
		case 0:
			g.DrawRegularPolygon(u.GlobalRand1.Intn(8), rf(320), rf(120), rf(noiseSize), rf(360))
		case 1:
			g.DrawEllipticalArc(rf(320), rf(120), rf(noiseSize), rf(noiseSize), rf(10), rf(10))
		case 2:
			g.DrawRoundedRectangle(rf(320), rf(120), rf(noiseSize), rf(noiseSize), rf(10))
		case 3:
			g.DrawRectangle(rf(320), rf(120), rf(noiseSize), rf(noiseSize))
		}

		if u.GlobalRand1.Intn(3) != 1 {
			g.Fill()
		} else {
			g.Stroke()
		}
	}

	err := g.EncodePNG(buf)
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func ri1s(n int) string {
	return u.String(u.GlobalRand1.Intn(n))
}

func ri2s(n int) string {
	return u.String(u.GlobalRand2.Intn(n))
}

func rf(n float64) float64 {
	return float64(u.GlobalRand1.Intn(int(n*100))) / 100
}
