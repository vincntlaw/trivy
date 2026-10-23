package packagesprops_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	config "github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/packagesprops"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string // Test input file
		inputFile string
		want      []ftypes.Package
		wantErr   string
	}{
		{
			name:      "PackagesProps",
			inputFile: "testdata/packages.props",
			want: []ftypes.Package{
				{Name: "ExactVersion", Version: "4.7.0", ID: "ExactVersion@4.7.0"},
				{Name: "ExactVersionWithEqualBounds", Version: "2.0.0", ID: "ExactVersionWithEqualBounds@2.0.0"},
				{Name: "ExactVersionWithSpaces", Version: "1.2.3", ID: "ExactVersionWithSpaces@1.2.3"},
				{Name: "Microsoft.Extensions.Configuration", Version: "2.1.1", ID: "Microsoft.Extensions.Configuration@2.1.1"},
				{Name: "Microsoft.Extensions.DependencyInjection.Abstractions", Version: "2.2.1", ID: "Microsoft.Extensions.DependencyInjection.Abstractions@2.2.1"},
				{Name: "Microsoft.Extensions.Http", Version: "3.2.1", ID: "Microsoft.Extensions.Http@3.2.1"},
			},
		},
		{
			name:      "VersionRanges",
			inputFile: "testdata/version_ranges.props",
			want: []ftypes.Package{
				{Name: "EmptyBrackets", Version: "[]", ID: "EmptyBrackets@[]"},
				{Name: "EmptyRange", Version: "(1.0,1.0)", ID: "EmptyRange@(1.0,1.0)"},
				{Name: "ExactLowerBound", Version: "[8.0.32,9)", ID: "ExactLowerBound@[8.0.32,9)"},
				{Name: "MaximumVersion", Version: "(,2.0]", ID: "MaximumVersion@(,2.0]"},
				{Name: "MinimumVersion", Version: "[1.0,)", ID: "MinimumVersion@[1.0,)"},
				{Name: "PlainVersion", Version: "3.1.4", ID: "PlainVersion@3.1.4"},
				{Name: "UnclosedBracket", Version: "[1.0", ID: "UnclosedBracket@[1.0"},
				{Name: "Variable", Version: "[$(Version)]", ID: "Variable@[$(Version)]"},
				{Name: "VersionInterval", Version: "(1.0,2.0)", ID: "VersionInterval@(1.0,2.0)"},
			},
		},
		{
			name:      "DirectoryPackagesProps",
			inputFile: "testdata/Directory.Packages.props",
			want: []ftypes.Package{
				{Name: "PackageOne", Version: "6.2.3", ID: "PackageOne@6.2.3"},
				{Name: "PackageThree", Version: "2.4.1", ID: "PackageThree@2.4.1"},
				{Name: "PackageTwo", Version: "6.0.0", ID: "PackageTwo@6.0.0"},
			},
		},
		{
			name:      "SeveralItemGroupElements",
			inputFile: "testdata/several_item_groups",
			want: []ftypes.Package{
				{Name: "PackageOne", Version: "6.2.3", ID: "PackageOne@6.2.3"},
				{Name: "PackageThree", Version: "2.4.1", ID: "PackageThree@2.4.1"},
				{Name: "PackageTwo", Version: "6.0.0", ID: "PackageTwo@6.0.0"},
			},
		},
		{
			name:      "VariablesAsNamesOrVersion",
			inputFile: "testdata/variables_and_empty",
			want: []ftypes.Package{
				{Name: "PackageFour", Version: "2.4.1", ID: "PackageFour@2.4.1"},
			},
		},
		{
			name:      "NoItemGroupInXMLStructure",
			inputFile: "testdata/no_item_group.props",
			want:      []ftypes.Package(nil),
		},
		{
			name:      "NoProject",
			inputFile: "testdata/no_project.props",
			wantErr:   "failed to decode '*.packages.props' file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			got, _, err := config.NewParser().Parse(t.Context(), f)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
