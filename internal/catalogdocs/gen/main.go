// Command gen regenerates the scanner catalog pages of the user guide from
// the Tool Catalog. Run it from the repository root, through `make docs`.
package main

import (
	"fmt"
	"os"

	"github.com/argusappsec/argus/internal/catalogdocs"
	"github.com/argusappsec/argus/pkg/security"
)

func main() {
	pages, err := catalogdocs.Render(security.Catalog())
	if err == nil {
		err = catalogdocs.Write(catalogdocs.Dir, pages)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d pages to %s\n", len(pages), catalogdocs.Dir)
}
