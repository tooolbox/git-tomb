// git-remote-tomb is the git remote helper for tomb-encrypted repos.
//
// Git invokes this automatically for URLs like tomb::https://github.com/user/repo.git
//
// Install: go install github.com/tooolbox/git-tomb/cmd/...@latest
package main

import (
	"fmt"
	"os"

	"github.com/tooolbox/git-tomb/remote"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: git-remote-tomb <remote-name> <url>\n")
		fmt.Fprintf(os.Stderr, "This is a git remote helper. Use it via: git clone tomb::https://...\n")
		os.Exit(1)
	}

	if err := remote.Run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "tomb: %v\n", err)
		os.Exit(1)
	}
}
