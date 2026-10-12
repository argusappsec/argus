package main

import (
	"fmt"
	"os"

	"example.com/vulnfixture/internal/tags"
	"golang.org/x/text/language"
)

func main() {
	for _, arg := range os.Args[1:] {
		tag, err := language.Parse(arg)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println(tag)
	}
	fmt.Println(tags.Normalise(os.Getenv("LANG")))
	fmt.Println(tags.One("en"))
}
