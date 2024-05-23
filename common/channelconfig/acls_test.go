package channelconfig

import (
	"testing"

	"github.com/11090815/mayy/protobuf/ppeer"
	"github.com/stretchr/testify/require"
)

const (
	api1_name       = "Foo"
	api1_policy_ref = "foo"

	api2_name       = "Bar"
	api2_policy_ref = "/Channel/bar"
)

var apisProvider = map[string]*ppeer.APIResource{
	api1_name: {PolicyRef: api1_policy_ref},
	api2_name: {PolicyRef: api2_policy_ref},
}

func TestGreenAPIsPath(t *testing.T) {
	provider := newAPIsProvider(apisProvider)
	require.NotNil(t, provider)

	require.Equal(t, "/Channel/Application/" + api1_policy_ref, provider.PolicyRefForAPI(api1_name))
	require.Equal(t, api2_policy_ref, provider.PolicyRefForAPI(api2_name))
	require.Empty(t, provider.PolicyRefForAPI("unknown"))
}

func TestNilACLs(t *testing.T) {
	provider := newAPIsProvider(nil)
	require.NotNil(t, provider)
	require.NotNil(t, provider.aclPolicyRefs)
	require.Empty(t, provider.aclPolicyRefs)	
}

func TestEmptyACLs(t *testing.T) {
	provider := newAPIsProvider(map[string]*ppeer.APIResource{})
	require.NotNil(t, provider)
	require.NotNil(t, provider.aclPolicyRefs)
	require.Empty(t, provider.aclPolicyRefs)	
}

func TestEmptyPolicyRef(t *testing.T) {
	ars := map[string]*ppeer.APIResource{
		"unsetAPI": {PolicyRef: ""},
	}

	provider := newAPIsProvider(ars)

	require.NotNil(t, provider)
	require.NotNil(t, provider.aclPolicyRefs)
	require.Empty(t, provider.aclPolicyRefs)

	ars = map[string]*ppeer.APIResource{
		"unsetAPI": {PolicyRef: ""},
		"setAPI": {PolicyRef: api2_policy_ref},
	}
	provider = newAPIsProvider(ars)

	require.NotNil(t, provider)
	require.NotNil(t, provider.aclPolicyRefs)
	require.NotEmpty(t, provider.aclPolicyRefs)
	require.NotContains(t, provider.aclPolicyRefs, api1_name)
}
