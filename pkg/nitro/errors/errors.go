package errors

import (
	"errors"

	"github.com/dollarshaveclub/acyl/pkg/nitro/images"
	"github.com/dollarshaveclub/acyl/pkg/nitro/meta"
)

var systemErrors = []error{
	meta.ErrGetFileContents,
	meta.ErrGetDirectoryContents,
	meta.ErrGetRepoBranches,
	meta.ErrGetRefForRepo,
	meta.ErrCreatingDirectory,
	meta.ErrCreatingSymlink,
	meta.ErrCreatingFile,
	meta.ErrWritingFile,
	meta.ErrShortWrite,
	meta.ErrNilLocation,
	images.ErrBuildingImage,
}

var userErrors = []error{
	meta.ErrYAMLSyntax,
	meta.ErrEmptyArg,
	meta.ErrUnsupportedVersion,
	meta.ErrNilParent,
	meta.ErrNilAncestor,
	meta.ErrNilDependency,
	meta.ErrMissingPath,
	meta.ErrMultipleDependency,
	meta.ErrDuplicateDependency,
	meta.ErrBranchAndRepo,
	meta.ErrValidateDependencyNames,
	meta.ErrMalformedValueOverride,
	meta.ErrMalformedRepoPath,
}

var cancelledErrors = []error{
	meta.ErrContextCancelled,
}

// IsUserError finds the first nitro error in the chain and returns true if it is a user error.
func IsUserError(err error) bool {
	for _, uErr := range userErrors {
		if errors.Is(err, uErr) {
			return true
		}
	}
	return false
}

// IsSystemError finds the first nitro error in the chain and returns true if it is a system error.
func IsSystemError(err error) bool {
	for _, sErr := range systemErrors {
		if errors.Is(err, sErr) {
			return true
		}
	}
	return false
}

// IsCancelledError finds the first nitro error in the chain and returns true if it is an error caused by a cancelled context.
func IsCancelledError(err error) bool {
	for _, cErr := range cancelledErrors {
		if errors.Is(err, cErr) {
			return true
		}
	}
	return false
}
