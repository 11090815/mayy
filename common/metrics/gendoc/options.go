package gendoc

import (
	"go/ast"
	"path"
	"reflect"
	"strconv"
	"strings"

	"github.com/11090815/mayy/common/metrics"
	"github.com/11090815/mayy/errors"
)

func FileOptions(f *ast.File) ([]any, error) {
	imports := walkImports(f)
	var options []any
	var errors []error

	for _, c := range f.Comments {
		for _, c := range c.List {
			if strings.HasPrefix(c.Text, "//gendoc:ignore") {
				return nil, nil
			}
		}
	}

	for i := range f.Decls {
		ast.Inspect(f.Decls[i], func(n ast.Node) bool {
			node, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}

			for _, v := range node.Values {
				value, ok := v.(*ast.CompositeLit)
				if !ok {
					continue
				}
				literalType, ok := value.Type.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				ident, ok := literalType.X.(*ast.Ident)
				if !ok {
					continue
				}
				if imports[ident.Name] != "github.com/11090815/mayy/common/metrics" {
					continue
				}
				option, err := createOption(literalType)
				if err != nil {
					errors = append(errors, err)
					break
				}
				option, err = populateOption(value, option)
				if err != nil {
					errors = append(errors, err)
					break
				}
				options = append(options, option)
			}
			return false
		})
	}

	if len(errors) != 0 {
		return nil, errors[0]
	}

	return options, nil
}

func walkImports(f *ast.File) map[string]string {
	imports := map[string]string{}

	for i := range f.Imports {
		ast.Inspect(f.Imports[i], func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ImportSpec:
				importPath, err := strconv.Unquote(node.Path.Value)
				if err != nil {
					panic(err)
				}
				importName := path.Base(importPath)
				if node.Name != nil {
					importName = node.Name.Name
				}
				imports[importName] = importPath
				return false
			default:
				return true
			}
		})
	}

	return imports
}

func createOption(selector *ast.SelectorExpr) (any, error) {
	optionName := selector.Sel.Name
	switch optionName {
	case "CounterOpts":
		return &metrics.CounterOpts{}, nil
	case "GaugeOpts":
		return &metrics.GaugeOpts{}, nil
	case "HistogramOpts":
		return &metrics.HistogramOpts{}, nil
	default:
		return nil, errors.NewErrorf("unknown option type: %s", optionName)
	}
}

func populateOption(list *ast.CompositeLit, target any) (any, error) {
	val := reflect.ValueOf(target).Elem()
	for _, elem := range list.Elts {
		if kv, ok := elem.(*ast.KeyValueExpr); ok {
			name := kv.Key.(*ast.Ident).Name
			field := val.FieldByName(name)

			switch name {
			case "Buckets":
				// 忽略
			case "LabelHelp":
				labelHelp, err := asStringMap(kv.Value.(*ast.CompositeLit))
				if err != nil {
					return nil, err
				}
				labelHelpValue := reflect.ValueOf(labelHelp)
				field.Set(labelHelpValue)
			case "LabelNames":
				labelNames, err := stringSlice(kv.Value.(*ast.CompositeLit))
				if err != nil {
					return nil, err
				}
				labelNamesValue := reflect.ValueOf(labelNames)
				field.Set(labelNamesValue)
			case "Namespace", "Subsystem", "Name", "Help", "StatsdFormat":
				basicVal := kv.Value.(*ast.BasicLit)
				val, err := strconv.Unquote(basicVal.Value)
				if err != nil {
					return nil, err
				}
				field.SetString(val)
			default:
				return nil, errors.NewErrorf("unknown field name: %s", name)
			}
		}
	}

	return val.Interface(), nil
}

func asStringMap(list *ast.CompositeLit) (map[string]string, error) {
	res := make(map[string]string)

	for _, elem := range list.Elts {
		elem := elem.(*ast.KeyValueExpr)
		key, err := strconv.Unquote(elem.Key.(*ast.BasicLit).Value)
		if err != nil {
			return nil, err
		}
		value, err := strconv.Unquote(elem.Value.(*ast.BasicLit).Value)
		if err != nil {
			return nil, err
		}
		res[key] = value
	}

	return res, nil
}

func stringSlice(list *ast.CompositeLit) ([]string, error) {
	var res []string

	for _, elem := range list.Elts {
		val, err := strconv.Unquote(elem.(*ast.BasicLit).Value)
		if err != nil {
			return nil, err
		}
		res = append(res, val)
	}

	return res, nil
}
