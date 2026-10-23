package packagesprops

import (
	"context"
	"encoding/xml"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Pkg struct {
	Version            string `xml:"Version,attr"`
	UpdatePackageName  string `xml:"Update,attr"`
	IncludePackageName string `xml:"Include,attr"`
}

// https://github.com/dotnet/roslyn-tools/blob/b4c5220f5dfc4278847b6d38eff91cc1188f8066/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L150
type itemGroup struct {
	PackageReferenceEntry []Pkg `xml:"PackageReference"`
	PackageVersionEntry   []Pkg `xml:"PackageVersion"`
}

type project struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []itemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p Pkg) Package() ftypes.Package {
	// Update attribute is considered legacy, so preferring Include
	name := p.UpdatePackageName
	if p.IncludePackageName != "" {
		name = p.IncludePackageName
	}

	name = strings.TrimSpace(name)
	version := exactVersion(p.Version)
	return ftypes.Package{
		ID:      dependency.ID(ftypes.NuGet, name, version),
		Name:    name,
		Version: version,
	}
}

// versionPattern matches a NuGet version: 1 to 4 numeric parts with an optional pre-release label
// and build metadata, e.g. `4.7.0`, `1.0.0-rc.1` and `1.2.3.4`.
var versionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// exactVersion returns the version for the ranges that specify exactly one version,
// e.g. `[4.7.0]` and `[4.7.0,4.7.0]`. Any other value is returned as is (after trimming spaces),
// because ranges that don't specify a single version are out of scope and their handling
// must not be changed.
// cf. https://learn.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges
func exactVersion(s string) string {
	s = strings.TrimSpace(s)

	// Only inclusive bounds can specify exactly one version.
	// `(1.0,1.0)` and `[1.0,1.0)` are empty ranges.
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return s
	}

	lower, upper, isRange := strings.Cut(s[1:len(s)-1], ",")
	lower, upper = strings.TrimSpace(lower), strings.TrimSpace(upper)

	// `[1.0]` - a single version. `[1.0,1.0]` - bounds specifying the same version.
	if isRange && lower != upper {
		return s
	}

	// Empty and malformed values (`[]`, `[1.0`) as well as unresolved variables
	// (`[$(Version)]`) are not versions, so they are left untouched.
	if !versionPattern.MatchString(lower) {
		return s
	}

	return lower
}

func shouldSkipPkg(pkg ftypes.Package) bool {
	if pkg.Name == "" || pkg.Version == "" {
		return true
	}
	// *packages.props files don't contain variable resolution information.
	// So we need to skip them.
	if isVariable(pkg.Name) || isVariable(pkg.Version) {
		return true
	}
	return false
}

func isVariable(s string) bool {
	return strings.HasPrefix(s, "$(") && strings.HasSuffix(s, ")")
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var configData project
	if err := xml.NewDecoder(r).Decode(&configData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode '*.packages.props' file: %w", err)
	}

	var pkgs []ftypes.Package
	for _, item := range configData.ItemGroups {
		for _, pkg := range append(item.PackageReferenceEntry, item.PackageVersionEntry...) {
			pkg := pkg.Package()
			if !shouldSkipPkg(pkg) {
				pkgs = append(pkgs, pkg)
			}
		}
	}
	return utils.UniquePackages(pkgs), nil, nil
}
