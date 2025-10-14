package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

// The user resource type is for all user objects from Okta.
var userResourceType = &v2.ResourceType{
	Id:          "user",
	DisplayName: "User",
	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
}

// The group resource type is for all group objects from Okta.
var groupResourceType = &v2.ResourceType{
	Id:          "group",
	DisplayName: "Group",
	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
}

// The role resource type is for all role objects from Okta.
var roleResourceType = &v2.ResourceType{
	Id:          "role",
	DisplayName: "Role",
	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
}

// The custom role resource type is for all custom role objects from Okta.
var customRoleResourceType = &v2.ResourceType{
	Id:          "custom-role",
	DisplayName: "Custom Role",
	Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
}
