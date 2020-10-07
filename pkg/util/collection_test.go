package util

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStringSliceToSet(t *testing.T) {

	t.Run("when slice contains duplicate elements then it is removed from the output", func(t *testing.T) {
		in := []string{"one", "one", "two", "one"}
		out := StringSliceToSet(in)

		require.Equal(t, 2, len(out))
		assert.Equal(t, "one", out[0])
		assert.Equal(t, "two", out[1])
		require.Equal(t, 4, len(in))
	})
}

func TestStringSliceContains(t *testing.T) {

	t.Run("when slice contains searched element then true is returned", func(t *testing.T) {

		s := []string{"default", "test", "*", "sandbox"}
		found := StringSliceContains(s, "*")
		assert.True(t, found)
	})

	t.Run("when slice does not contain searched element then false is returned", func(t *testing.T) {

		s := []string{"default", "test", "*", "sandbox"}
		found := StringSliceContains(s, "production")
		assert.False(t, found)
	})
}
