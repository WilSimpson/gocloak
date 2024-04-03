package gocloak

import (
	"context"

	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
)

type KeycloakClient interface {
	RestyClient() *resty.Client
	SetRestyClient(restyClient *resty.Client)

	GetToken(ctx context.Context, realm string, options TokenOptions) (*JWT, error)
	GetRequestingPartyToken(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*JWT, error)
	GetRequestingPartyPermissions(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*[]RequestingPartyPermission, error)
	GetRequestingPartyPermissionDecision(ctx context.Context, token, realm string, options RequestingPartyTokenOptions) (*RequestingPartyPermissionDecision, error)

	Login(ctx context.Context, clientID, clientSecret, realm, username, password string) (*JWT, error)
	LoginOtp(ctx context.Context, clientID, clientSecret, realm, username, password, totp string) (*JWT, error)
	Logout(ctx context.Context, clientID, clientSecret, realm, refreshToken string) error
	LogoutPublicClient(ctx context.Context, clientID, realm, accessToken, refreshToken string) error
	LogoutAllSessions(ctx context.Context, accessToken, realm, userID string) error
	RevokeUserConsents(ctx context.Context, accessToken, realm, userID, clientID string) error
	LogoutUserSession(ctx context.Context, accessToken, realm, session string) error
	LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*JWT, error)
	LoginClientSignedJWT(ctx context.Context, clientID, realm string, key interface{}, signedMethod jwt.SigningMethod, expiresAt *jwt.NumericDate) (*JWT, error)
	LoginAdmin(ctx context.Context, username, password, realm string) (*JWT, error)
	RefreshToken(ctx context.Context, refreshToken, clientID, clientSecret, realm string) (*JWT, error)
	DecodeAccessToken(ctx context.Context, accessToken, realm string) (*jwt.Token, *jwt.MapClaims, error)
	DecodeAccessTokenCustomClaims(ctx context.Context, accessToken, realm string, claims jwt.Claims) (*jwt.Token, error)
	RetrospectToken(ctx context.Context, accessToken, clientID, clientSecret, realm string) (*IntroSpectTokenResult, error)
	GetIssuer(ctx context.Context, realm string) (*IssuerResponse, error)
	GetCerts(ctx context.Context, realm string) (*CertResponse, error)
	GetServerInfo(ctx context.Context, accessToken string) ([]*ServerInfoRepresentation, error)
	GetUserInfo(ctx context.Context, accessToken, realm string) (*UserInfo, error)
	GetRawUserInfo(ctx context.Context, accessToken, realm string) (map[string]interface{}, error)
	SetPassword(ctx context.Context, token, userID, realm, password string, temporary bool) error
	ExecuteActionsEmail(ctx context.Context, token, realm string, params ExecuteActionsEmail) error

	CreateUser(ctx context.Context, token, realm string, user User) (string, error)
	CreateGroup(ctx context.Context, accessToken, realm string, group Group) (string, error)
	CreateChildGroup(ctx context.Context, token, realm, groupID string, group Group) (string, error)
	CreateClientRole(ctx context.Context, accessToken, realm, idOfClient string, role Role) (string, error)
	CreateClient(ctx context.Context, accessToken, realm string, newClient Client) (string, error)
	CreateClientScope(ctx context.Context, accessToken, realm string, scope ClientScope) (string, error)
	CreateComponent(ctx context.Context, accessToken, realm string, component Component) (string, error)
	CreateClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error
	CreateClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error
	CreateClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfCLientScope string, roles []Role) error
	CreateClientScopesScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClientScope, idOfClient string, roles []Role) error

	UpdateUser(ctx context.Context, accessToken, realm string, user User) error
	UpdateGroup(ctx context.Context, accessToken, realm string, updatedGroup Group) error
	UpdateRole(ctx context.Context, accessToken, realm, idOfClient string, role Role) error
	UpdateClient(ctx context.Context, accessToken, realm string, updatedClient Client) error
	UpdateClientScope(ctx context.Context, accessToken, realm string, scope ClientScope) error

	DeleteUser(ctx context.Context, accessToken, realm, userID string) error
	DeleteComponent(ctx context.Context, accessToken, realm, componentID string) error
	DeleteGroup(ctx context.Context, accessToken, realm, groupID string) error
	DeleteClientRole(ctx context.Context, accessToken, realm, idOfClient, roleName string) error
	DeleteClientRoleFromUser(ctx context.Context, token, realm, idOfClient, userID string, roles []Role) error
	DeleteClient(ctx context.Context, accessToken, realm, idOfClient string) error
	DeleteClientScope(ctx context.Context, accessToken, realm, scopeID string) error
	DeleteClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string, roles []Role) error
	DeleteClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string, roles []Role) error
	DeleteClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfCLientScope string, roles []Role) error
	DeleteClientScopesScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClientScope, ifOfClient string, roles []Role) error

	GetClient(ctx context.Context, accessToken, realm, idOfClient string) (*Client, error)
	GetClientsDefaultScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error)
	AddDefaultScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error
	RemoveDefaultScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error
	GetClientsOptionalScopes(ctx context.Context, token, realm, idOfClient string) ([]*ClientScope, error)
	AddOptionalScopeToClient(ctx context.Context, token, realm, idOfClient, scopeID string) error
	RemoveOptionalScopeFromClient(ctx context.Context, token, realm, idOfClient, scopeID string) error
	GetDefaultOptionalClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	GetDefaultDefaultClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	GetClientScope(ctx context.Context, token, realm, scopeID string) (*ClientScope, error)
	GetClientScopes(ctx context.Context, token, realm string) ([]*ClientScope, error)
	GetClientScopeMappings(ctx context.Context, token, realm, idOfClient string) (*MappingsRepresentation, error)
	GetClientScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClient string) ([]*Role, error)
	GetClientScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, idOfClient string) ([]*Role, error)
	GetClientScopesScopeMappingsRealmRolesAvailable(ctx context.Context, token, realm, idOfClientScope string) ([]*Role, error)
	GetClientScopesScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, idOfClientScope, idOfClient string) ([]*Role, error)
	GetClientScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error)
	GetClientScopesScopeMappingsRealmRoles(ctx context.Context, token, realm, idOfClientScope string) ([]*Role, error)
	GetClientScopesScopeMappingsClientRoles(ctx context.Context, token, realm, idOfClientScope, idOfClient string) ([]*Role, error)
	GetClientScopeMappingsClientRolesAvailable(ctx context.Context, token, realm, idOfClient, idOfSelectedClient string) ([]*Role, error)
	GetClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error)
	GetClientServiceAccount(ctx context.Context, token, realm, idOfClient string) (*User, error)
	RegenerateClientSecret(ctx context.Context, token, realm, idOfClient string) (*CredentialRepresentation, error)
	GetKeyStoreConfig(ctx context.Context, accessToken, realm string) (*KeyStoreConfig, error)
	GetUserByID(ctx context.Context, accessToken, realm, userID string) (*User, error)
	GetUserCount(ctx context.Context, accessToken, realm string, params GetUsersParams) (int, error)
	GetUsers(ctx context.Context, accessToken, realm string, params GetUsersParams) ([]*User, error)
	GetUserGroups(ctx context.Context, token, realm, userID string, params GetGroupsParams) ([]*Group, error)
	AddUserToGroup(ctx context.Context, token, realm, userID, groupID string) error
	DeleteUserFromGroup(ctx context.Context, token, realm, userID, groupID string) error
	GetComponents(ctx context.Context, accessToken, realm string) ([]*Component, error)
	GetGroups(ctx context.Context, accessToken, realm string, params GetGroupsParams) ([]*Group, error)
	GetGroupsCount(ctx context.Context, token, realm string, params GetGroupsParams) (int, error)
	GetGroup(ctx context.Context, accessToken, realm, groupID string) (*Group, error)
	GetDefaultGroups(ctx context.Context, accessToken, realm string) ([]*Group, error)
	AddDefaultGroup(ctx context.Context, accessToken, realm, groupID string) error
	RemoveDefaultGroup(ctx context.Context, accessToken, realm, groupID string) error
	GetGroupMembers(ctx context.Context, accessToken, realm, groupID string, params GetGroupsParams) ([]*User, error)
	GetRoleMappingByGroupID(ctx context.Context, accessToken, realm, groupID string) (*MappingsRepresentation, error)
	GetRoleMappingByUserID(ctx context.Context, accessToken, realm, userID string) (*MappingsRepresentation, error)
	GetClientRoles(ctx context.Context, accessToken, realm, idOfClient string, params GetRoleParams) ([]*Role, error)
	GetClientRole(ctx context.Context, token, realm, idOfClient, roleName string) (*Role, error)
	GetClientRoleByID(ctx context.Context, accessToken, realm, roleID string) (*Role, error)
	GetClients(ctx context.Context, accessToken, realm string, params GetClientsParams) ([]*Client, error)
	AddClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error
	DeleteClientRoleComposite(ctx context.Context, token, realm, roleID string, roles []Role) error
	GetUsersByRoleName(ctx context.Context, token, realm, roleName string, params GetUsersByRoleParams) ([]*User, error)
	GetUsersByClientRoleName(ctx context.Context, token, realm, idOfClient, roleName string, params GetUsersByRoleParams) ([]*User, error)
	CreateClientProtocolMapper(ctx context.Context, token, realm, idOfClient string, mapper ProtocolMapperRepresentation) (string, error)
	UpdateClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string, mapper ProtocolMapperRepresentation) error
	DeleteClientProtocolMapper(ctx context.Context, token, realm, idOfClient, mapperID string) error

	// *** Realm Roles ***

	CreateRealmRole(ctx context.Context, token, realm string, role Role) (string, error)
	GetRealmRole(ctx context.Context, token, realm, roleName string) (*Role, error)
	GetRealmRoles(ctx context.Context, accessToken, realm string, params GetRoleParams) ([]*Role, error)
	GetRealmRoleByID(ctx context.Context, token, realm, roleID string) (*Role, error)
	GetRealmRolesByUserID(ctx context.Context, accessToken, realm, userID string) ([]*Role, error)
	GetRealmRolesByGroupID(ctx context.Context, accessToken, realm, groupID string) ([]*Role, error)
	UpdateRealmRole(ctx context.Context, token, realm, roleName string, role Role) error
	UpdateRealmRoleByID(ctx context.Context, token, realm, roleID string, role Role) error
	DeleteRealmRole(ctx context.Context, token, realm, roleName string) error
	AddRealmRoleToUser(ctx context.Context, token, realm, userID string, roles []Role) error
	DeleteRealmRoleFromUser(ctx context.Context, token, realm, userID string, roles []Role) error
	AddRealmRoleToGroup(ctx context.Context, token, realm, groupID string, roles []Role) error
	DeleteRealmRoleFromGroup(ctx context.Context, token, realm, groupID string, roles []Role) error
	AddRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error
	DeleteRealmRoleComposite(ctx context.Context, token, realm, roleName string, roles []Role) error
	GetCompositeRealmRoles(ctx context.Context, token, realm, roleName string) ([]*Role, error)
	GetCompositeRealmRolesByRoleID(ctx context.Context, token, realm, roleID string) ([]*Role, error)
	GetCompositeRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error)
	GetCompositeRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error)
	GetAvailableRealmRolesByUserID(ctx context.Context, token, realm, userID string) ([]*Role, error)
	GetAvailableRealmRolesByGroupID(ctx context.Context, token, realm, groupID string) ([]*Role, error)

	// *** Client Roles ***

	AddClientRoleToUser(ctx context.Context, token, realm, idOfClient, userID string, roles []Role) error
	AddClientRoleToGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error
	DeleteClientRoleFromGroup(ctx context.Context, token, realm, idOfClient, groupID string, roles []Role) error
	GetCompositeClientRolesByRoleID(ctx context.Context, token, realm, idOfClient, roleID string) ([]*Role, error)
	GetClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error)
	GetClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error)
	GetCompositeClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error)
	GetCompositeClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error)
	GetAvailableClientRolesByUserID(ctx context.Context, token, realm, idOfClient, userID string) ([]*Role, error)
	GetAvailableClientRolesByGroupID(ctx context.Context, token, realm, idOfClient, groupID string) ([]*Role, error)

	// *** Realm ***

	GetRealm(ctx context.Context, token, realm string) (*RealmRepresentation, error)
	GetRealms(ctx context.Context, token string) ([]*RealmRepresentation, error)
	CreateRealm(ctx context.Context, token string, realm RealmRepresentation) (string, error)
	UpdateRealm(ctx context.Context, token string, realm RealmRepresentation) error
	DeleteRealm(ctx context.Context, token, realm string) error
	ClearRealmCache(ctx context.Context, token, realm string) error
	ClearUserCache(ctx context.Context, token, realm string) error
	ClearKeysCache(ctx context.Context, token, realm string) error

	GetClientUserSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error)
	GetClientOfflineSessions(ctx context.Context, token, realm, idOfClient string) ([]*UserSessionRepresentation, error)
	GetUserSessions(ctx context.Context, token, realm, userID string) ([]*UserSessionRepresentation, error)
	GetUserOfflineSessionsForClient(ctx context.Context, token, realm, userID, idOfClient string) ([]*UserSessionRepresentation, error)

	// *** Protection API ***
	GetResource(ctx context.Context, token, realm, idOfClient, resourceID string) (*ResourceRepresentation, error)
	GetResources(ctx context.Context, token, realm, idOfClient string, params GetResourceParams) ([]*ResourceRepresentation, error)
	CreateResource(ctx context.Context, token, realm, idOfClient string, resource ResourceRepresentation) (*ResourceRepresentation, error)
	UpdateResource(ctx context.Context, token, realm, idOfClient string, resource ResourceRepresentation) error
	DeleteResource(ctx context.Context, token, realm, idOfClient, resourceID string) error

	GetResourceClient(ctx context.Context, token, realm, resourceID string) (*ResourceRepresentation, error)
	GetResourcesClient(ctx context.Context, token, realm string, params GetResourceParams) ([]*ResourceRepresentation, error)
	CreateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) (*ResourceRepresentation, error)
	UpdateResourceClient(ctx context.Context, token, realm string, resource ResourceRepresentation) error
	DeleteResourceClient(ctx context.Context, token, realm, resourceID string) error

	GetScope(ctx context.Context, token, realm, idOfClient, scopeID string) (*ScopeRepresentation, error)
	GetScopes(ctx context.Context, token, realm, idOfClient string, params GetScopeParams) ([]*ScopeRepresentation, error)
	CreateScope(ctx context.Context, token, realm, idOfClient string, scope ScopeRepresentation) (*ScopeRepresentation, error)
	UpdateScope(ctx context.Context, token, realm, idOfClient string, resource ScopeRepresentation) error
	DeleteScope(ctx context.Context, token, realm, idOfClient, scopeID string) error

	GetPolicy(ctx context.Context, token, realm, idOfClient, policyID string) (*PolicyRepresentation, error)
	GetPolicies(ctx context.Context, token, realm, idOfClient string, params GetPolicyParams) ([]*PolicyRepresentation, error)
	CreatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) (*PolicyRepresentation, error)
	UpdatePolicy(ctx context.Context, token, realm, idOfClient string, policy PolicyRepresentation) error
	DeletePolicy(ctx context.Context, token, realm, idOfClient, policyID string) error

	GetResourcePolicy(ctx context.Context, token, realm, permissionID string) (*ResourcePolicyRepresentation, error)
	GetResourcePolicies(ctx context.Context, token, realm string, params GetResourcePoliciesParams) ([]*ResourcePolicyRepresentation, error)
	CreateResourcePolicy(ctx context.Context, token, realm, resourceID string, policy ResourcePolicyRepresentation) (*ResourcePolicyRepresentation, error)
	UpdateResourcePolicy(ctx context.Context, token, realm, permissionID string, policy ResourcePolicyRepresentation) error
	DeleteResourcePolicy(ctx context.Context, token, realm, permissionID string) error

	GetPermission(ctx context.Context, token, realm, idOfClient, permissionID string) (*PermissionRepresentation, error)
	GetPermissions(ctx context.Context, token, realm, idOfClient string, params GetPermissionParams) ([]*PermissionRepresentation, error)
	GetPermissionResources(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionResource, error)
	GetPermissionScopes(ctx context.Context, token, realm, idOfClient, permissionID string) ([]*PermissionScope, error)
	GetDependentPermissions(ctx context.Context, token, realm, idOfClient, policyID string) ([]*PermissionRepresentation, error)
	CreatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) (*PermissionRepresentation, error)
	UpdatePermission(ctx context.Context, token, realm, idOfClient string, permission PermissionRepresentation) error
	DeletePermission(ctx context.Context, token, realm, idOfClient, permissionID string) error

	CreatePermissionTicket(ctx context.Context, token, realm string, permissions []CreatePermissionTicketParams) (*PermissionTicketResponseRepresentation, error)
	GrantUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error)
	UpdateUserPermission(ctx context.Context, token, realm string, permission PermissionGrantParams) (*PermissionGrantResponseRepresentation, error)
	GetUserPermissions(ctx context.Context, token, realm string, params GetUserPermissionParams) ([]*PermissionGrantResponseRepresentation, error)
	DeleteUserPermission(ctx context.Context, token, realm, ticketID string) error

	// *** Credentials API ***

	GetCredentialRegistrators(ctx context.Context, token, realm string) ([]string, error)
	GetConfiguredUserStorageCredentialTypes(ctx context.Context, token, realm, userID string) ([]string, error)
	GetCredentials(ctx context.Context, token, realm, UserID string) ([]*CredentialRepresentation, error)
	DeleteCredentials(ctx context.Context, token, realm, UserID, CredentialID string) error
	UpdateCredentialUserLabel(ctx context.Context, token, realm, userID, credentialID, userLabel string) error
	DisableAllCredentialsByType(ctx context.Context, token, realm, userID string, types []string) error
	MoveCredentialBehind(ctx context.Context, token, realm, userID, credentialID, newPreviousCredentialID string) error
	MoveCredentialToFirst(ctx context.Context, token, realm, userID, credentialID string) error

	// *** Authentication Flows ***
	GetAuthenticationFlows(ctx context.Context, token, realm string) ([]*AuthenticationFlowRepresentation, error)
	GetAuthenticationFlow(ctx context.Context, token, realm string, authenticationFlowID string) (*AuthenticationFlowRepresentation, error)
	CreateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation) error
	UpdateAuthenticationFlow(ctx context.Context, token, realm string, flow AuthenticationFlowRepresentation, authenticationFlowID string) (*AuthenticationFlowRepresentation, error)
	DeleteAuthenticationFlow(ctx context.Context, token, realm, flowID string) error

	// *** Identity Providers ***

	CreateIdentityProvider(ctx context.Context, token, realm string, providerRep IdentityProviderRepresentation) (string, error)
	GetIdentityProvider(ctx context.Context, token, realm, alias string) (*IdentityProviderRepresentation, error)
	GetIdentityProviders(ctx context.Context, token, realm string) ([]*IdentityProviderRepresentation, error)
	UpdateIdentityProvider(ctx context.Context, token, realm, alias string, providerRep IdentityProviderRepresentation) error
	DeleteIdentityProvider(ctx context.Context, token, realm, alias string) error

	CreateIdentityProviderMapper(ctx context.Context, token, realm, alias string, mapper IdentityProviderMapper) (string, error)
	GetIdentityProviderMapper(ctx context.Context, token string, realm string, alias string, mapperID string) (*IdentityProviderMapper, error)
	CreateUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string, federatedIdentityRep FederatedIdentityRepresentation) error
	GetUserFederatedIdentities(ctx context.Context, token, realm, userID string) ([]*FederatedIdentityRepresentation, error)
	DeleteUserFederatedIdentity(ctx context.Context, token, realm, userID, providerID string) error

	// *** Events API ***
	GetEvents(ctx context.Context, token string, realm string, params GetEventsParams) ([]*EventRepresentation, error)
}
