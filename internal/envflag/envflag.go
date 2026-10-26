// Package envflag lets every flag also be set from an MP_* environment
// variable (-upload-limit ↔ MP_UPLOAD_LIMIT), which is how containers are
// configured. A flag given on the command line wins over the environment.
package envflag

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func Name(flagName string) string {
	return "MP_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// Parse applies MP_* variables to fs, then parses args over them.
func Parse(fs *flag.FlagSet, args []string) error {
	var errs []string
	fs.VisitAll(func(f *flag.Flag) {
		if v, ok := os.LookupEnv(Name(f.Name)); ok {
			if err := f.Value.Set(v); err != nil {
				errs = append(errs, fmt.Sprintf("%s=%q: %v", Name(f.Name), v, err))
			}
		}
	})
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return fs.Parse(args)
}
