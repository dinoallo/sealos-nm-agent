package mongo

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTimeSeriesUnsupportedErr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "timeseries not supported",
			err:  errors.New("BSON field 'create.timeseries' is an unknown field"),
			want: true,
		},
		{
			name: "timeseries unrecognized field",
			err:  errors.New("BSON field 'create.timeseries' is an unrecognized field"),
			want: true,
		},
		{
			name: "timeseries failed to parse",
			err:  errors.New("Failed to parse: timeseries is not supported by this deployment"),
			want: true,
		},
		{
			name: "timeseries explicit not supported",
			err:  errors.New("timeseries is not supported"),
			want: true,
		},
		{
			name: "non timeseries unknown field",
			err:  errors.New("BSON field 'create.capped' is an unknown field"),
			want: false,
		},
		{
			name: "permission error",
			err:  errors.New("not authorized on admin to execute command"),
			want: false,
		},
		{
			name: "generic parse error without timeseries",
			err:  errors.New("failed to parse create command"),
			want: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isTimeSeriesUnsupportedErr(tc.err))
		})
	}
}

func TestIsUnauthorizedErr(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "not authorized",
			err:  errors.New("not authorized on test to execute command"),
			want: true,
		},
		{
			name: "unauthorized",
			err:  errors.New("Unauthorized"),
			want: true,
		},
		{
			name: "permission denied",
			err:  errors.New("permission denied"),
			want: true,
		},
		{
			name: "timeseries unsupported",
			err:  errors.New("timeseries is not supported"),
			want: false,
		},
		{
			name: "generic error",
			err:  errors.New("some other mongo error"),
			want: false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isUnauthorizedErr(tc.err))
		})
	}
}
