//go:build mage

package main

import (
	"fmt"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

func GenerateAll() {
	mg.Deps(Init)
	mg.Deps(mg.F(Generate.mock, false))
	mg.Deps(mg.F(Generate.openAPI, false))
}

type Generate mg.Namespace

func (Generate) Mock() error {
	mg.Deps(mg.F(Generate.mock, true))
	mg.Deps(mg.F(Generate.openAPI, true))

	// Cover any new dependencies that may have been added by the code generation.
	return VendorDeps()
}

func (Generate) OpenAPI() error {
	mg.Deps(mg.F(Generate.openAPI, true))

	// Cover any new dependencies that may have been added by the code generation.
	return VendorDeps()
}

func (Generate) mock(shouldVendor bool) error {
	mg.Deps(Init)

	args := []string{
		"run",
		"//:gen_mock",
	}

	if err := sh.Run("bazel", args...); err != nil {
		return fmt.Errorf("error writing generated mock files: %w", err)
	}

	if shouldVendor {
		if err := VendorDeps(); err != nil {
			return err
		}
	}

	return nil
}

func (Generate) openAPI(shouldVendor bool) error {
	//mg.Deps(Init)

	args := []string{
		"run",
		"//:gen_openapi",
	}

	if err := sh.Run("bazel", args...); err != nil {
		return fmt.Errorf("error writing generated open-api files: %w", err)
	}

	if shouldVendor {
		return VendorDeps()
	}

	return nil
}
