package pylock

import (
	"context"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Pylock struct {
	Packages []Package `toml:"packages"`
}

type Package struct {
	Name         string       `toml:"name"`
	Version      string       `toml:"version"`
	Dependencies []Dependency `toml:"dependencies"`
	Directory    Directory    `toml:"directory"`
}

// root returns true if the package represents the project itself.
// `pip` includes the project as a package with non-empty [packages.directory.path]
// e.g. for `pip lock ./app` pylock.toml will contain a package with [packages.directory.path] = "app" which is the root package of the project.
// `poetry-plugin-export` doesn't currently include the project in pylock.toml.
func (p Package) root() bool {
	return p.Directory.Path != ""
}

type Directory struct {
	Path string `toml:"path"`
}

type Dependency struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

// Parser parses pylock.toml defined in PEP 751.
// https://peps.python.org/pep-0751
type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("pylock"),
	}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lock Pylock
	if _, err := toml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode pylock.toml: %w", err)
	}

	// PEP 751 allows a dependency to contain only the minimum set of keys that identifies
	// the `[[packages]]` entry unambiguously, so the version is omitted when the name is unique.
	// https://peps.python.org/pep-0751/#packages-dependencies
	pkgIDsByName := make(map[string][]string)
	for _, pkg := range lock.Packages {
		normalizedPkgName := python.NormalizePkgName(pkg.Name, true)
		pkgIDsByName[normalizedPkgName] = lo.Uniq(append(pkgIDsByName[normalizedPkgName], packageID(normalizedPkgName, pkg.Version)))
	}

	pkgs := make(map[string]ftypes.Package)
	deps := make(map[string][]string)

	for _, pkg := range lock.Packages {
		normalizedPkgName := python.NormalizePkgName(pkg.Name, true)
		pkgID := packageID(normalizedPkgName, pkg.Version)

		pkgs[pkgID] = ftypes.Package{
			ID:           pkgID,
			Name:         normalizedPkgName,
			Version:      pkg.Version,
			Relationship: lo.Ternary(pkg.root(), ftypes.RelationshipRoot, ftypes.RelationshipUnknown),
		}

		var dependsOn []string
		for _, dep := range pkg.Dependencies {
			depName := python.NormalizePkgName(dep.Name, true)
			depID, ok := p.resolveDependencyID(depName, dep.Version, pkgIDsByName)
			if !ok {
				continue
			}
			dependsOn = append(dependsOn, depID)
		}
		if len(dependsOn) > 0 {
			sort.Strings(dependsOn)
			deps[pkgID] = dependsOn
		}
	}

	depSlice := lo.MapToSlice(deps, func(pkgID string, dependsOn []string) ftypes.Dependency {
		if _, ok := pkgs[pkgID]; !ok {
			return ftypes.Dependency{}
		}

		// Filter out dependencies that are not in the package list
		var dependsOnIDs []string
		for _, depID := range dependsOn {
			if _, ok := pkgs[depID]; ok {
				dependsOnIDs = append(dependsOnIDs, depID)
			}
		}

		return ftypes.Dependency{
			ID:        pkgID,
			DependsOn: dependsOnIDs,
		}
	})

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(ftypes.Dependencies(depSlice))

	return pkgSlice, depSlice, nil
}

// resolveDependencyID returns the package ID of the dependency.
// `[[packages.dependencies]]` doesn't always contain a version, so a name-only selector
// is resolved against the packages listed in the lock file. Name-only selectors are
// ambiguous when several entries share the name (e.g. different versions per environment),
// in which case no dependency is returned rather than picking an arbitrary entry.
func (p *Parser) resolveDependencyID(name, ver string, idsByName map[string][]string) (string, bool) {
	if ver != "" {
		return packageID(name, ver), true
	}

	switch ids := idsByName[name]; len(ids) {
	case 1:
		return ids[0], true
	case 0:
		p.logger.Debug("Unable to resolve the dependency without a version: package not found",
			log.String("name", name))
		return "", false
	default:
		p.logger.Debug("Unable to resolve the dependency without a version: the name is ambiguous",
			log.String("name", name), log.Int("candidates", len(ids)))
		return "", false
	}
}

func packageID(name, ver string) string {
	return dependency.ID(ftypes.PyLock, name, ver)
}
