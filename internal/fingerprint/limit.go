package fingerprint

import "io"

func ioLimitReader(r io.Reader, n int64) io.Reader {
	return io.LimitReader(r, n)
}
