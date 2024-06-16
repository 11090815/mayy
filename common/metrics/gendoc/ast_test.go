package gendoc_test

import (
	"flag"
	"testing"

	"golang.org/x/tools/go/packages"
)

var templatesPath = flag.String("template", "docs/source/metrics_reference.rst", "The documentation template.")

func TestFlag(t *testing.T) {
	flag.Parse()
	patterns := flag.Args()

	t.Log(patterns)
}

func TestPackagesLoad(t *testing.T) {
	patterns := []string{"github.com/11090815/mayy/..."}
	// packages.NeedFiles：列出所有引用此包的 Go 文件
	// packages.NeedImports：列出此包引用的所有包
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedSyntax | packages.NeedTypesInfo
	pkgs, err := packages.Load(&packages.Config{Mode: mode}, patterns...)
	if err != nil {
		t.Logf("err1 [%s]", err.Error())
		return
	}
	for _, pkg := range pkgs {
		t.Log(pkg.Name, pkg.PkgPath, pkg.Imports)
	}
}
