from pydantic import BaseModel
from enum import Enum

class AuthProfileName(Enum): 
    planner = "planner"
    classifier = "classifier"
    patcher = "patcher"
    supervisor = "supervisor"
    admin = "admin"
    intent_registration_admin = "intent_registration_admin"

class GrantType(Enum): 
    authorization_code = "authorization_code"
    implicit = "implicit"
    password_credentials = "password_credentials"
    client_credenials = "client_credentials"

class OAuthConfig(BaseModel): 
    grant_type: GrantType = GrantType.client_credenials
    client_id: str
    client_secret: str
    scope: str
    audience: str

class AuthProfile(BaseModel): 
    id: AuthProfileName
    config: OAuthConfig
    description: str | None = None

token_profiles: dict[AuthProfileName, AuthProfile] = {
    AuthProfileName.planner: AuthProfile(
        id=AuthProfileName.planner,
        config=OAuthConfig(
            client_id=AuthProfileName.planner.value, 
            client_secret="planner-secret", 
            scope="classify plan read:repo read:sbom", 
            audience=""
        ), 
        description="Planner token profile."
    ), 
    AuthProfileName.patcher: AuthProfile(
        id=AuthProfileName.patcher,
        config=OAuthConfig(
            client_id=AuthProfileName.patcher.value, 
            client_secret="executor-secret", 
            scope="", 
            audience=""
        ), 
        description="Patcher token profile."
    ),
    AuthProfileName.admin: AuthProfile(
        id=AuthProfileName.admin,
        config=OAuthConfig(
            client_id=AuthProfileName.admin.value, 
            client_secret="too-much", 
            scope="", 
            audience=""
        ), 
        description="Admin token profile."
    ),
    AuthProfileName.intent_registration_admin: AuthProfile(
        id=AuthProfileName.intent_registration_admin,
        config=OAuthConfig(
            client_id=AuthProfileName.intent_registration_admin.value, 
            client_secret="intent-secret", 
            scope="", 
            audience=""
        ), 
        description="Admin token profile."
    )
}
