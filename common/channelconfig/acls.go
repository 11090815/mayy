package channelconfig

import (
	"github.com/11090815/mayy/common/mlog"
	"github.com/11090815/mayy/protobuf/ppeer"
)

var (
	logger = mlog.GetLogger("common.channelconfig", mlog.DebugLevel)
)

type aclsProvider struct {
	aclPolicyRefs map[string]string
}

func (provider *aclsProvider) PolicyRefForAPI(aclName string) string {
	return provider.aclPolicyRefs[aclName]
}

func newAPIsProvider(acls map[string]*ppeer.APIResource) *aclsProvider {
	aclPolicyRefs := make(map[string]string)

	for key, acl := range acls {
		if len(acl.PolicyRef) == 0 {
			logger.Warnf("Policy reference for resource \"%s\" is specified, but empty, falling back to default.", key)
			continue
		}

		if acl.PolicyRef[0] != '/' {
			aclPolicyRefs[key] = "/" + ChannelGroupKey + "/" + ApplicationGroupKey + "/" + acl.PolicyRef // /Channel/Application/PolicyRef
		} else {
			aclPolicyRefs[key] = acl.PolicyRef
		}
	}

	return &aclsProvider{
		aclPolicyRefs: aclPolicyRefs,
	}
}
