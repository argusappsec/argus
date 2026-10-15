package main

import (
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
)

func run(name string) error {
	return exec.Command("sh", "-c", name).Run()
}

func runQuietly(name string) error {
	return exec.Command("sh", "-c", name).Run() // #nosec G204 -- the caller is trusted
}

func digest(b []byte) string {
	//gosec:disable G401 -- not used for security
	h := md5.New()
	h.Write(b)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func main() {
	_ = run(os.Args[1])
	_ = runQuietly(os.Args[1])
	fmt.Println(digest([]byte(os.Args[1])))
}
